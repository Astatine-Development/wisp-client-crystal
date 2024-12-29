require "json"
require "http/web_socket"
require "log"

# Modified logging module
module WispLogger
  class_property logger = Log.for("wisp")

  def self.setup
    backend = Log::IOBackend.new(formatter: WispFormatter)
    Log.setup do |c|
      c.bind("wisp.*", :debug, backend)
    end
  end

  # Implement as a module instead
  module WispFormatter
    extend Log::Formatter

    def self.format(entry : Log::Entry, io : IO) : Nil
      io << Time.local.to_s("%H:%M:%S.%L") << " [" << entry.severity << "] "
      io << entry.message
      if ex = entry.exception
        io << " - Exception: " << ex.message
        io << "\n" << ex.backtrace.join("\n") if ex.backtrace
      end
      io << '\n'
    end
  end
end


WispLogger.setup

module Wisp
  @@connections = {} of String => Connection

  def self.get_connection(url : String) : Connection
    WispLogger.logger.debug { "Getting connection for URL: #{url}" }
    @@connections[url] ||= Connection.new(url)
  end

  PACKET_TYPES = {
    CONNECT:  0x01_u8,
    DATA:     0x02_u8,
    CONTINUE: 0x03_u8,
    CLOSE:    0x04_u8,
    PING:     0x05_u8,
    PONG:     0x06_u8,
  }

  def self.slice_from_uint(int : Int, size : Int32) : Bytes
    WispLogger.logger.debug { "Converting int #{int} to #{size} bytes" }
    bytes = Bytes.new(size)
    size.times do |i|
      bytes[i] = ((int >> (8 * i)) & 0xFF).to_u8
    end
    bytes
  end

  def self.uint_from_slice(slice : Bytes) : UInt32
    WispLogger.logger.debug { "Converting #{slice.size} bytes to uint" }
    case slice.size
    when 4 then slice.to_unsafe.as(UInt32*).value
    when 2 then slice.to_unsafe.as(UInt16*).value.to_u32
    when 1 then slice[0].to_u32
    else
      WispLogger.logger.error { "Invalid slice length: #{slice.size}" }
      raise "Invalid slice length"
    end
  end

  def self.concat_bytes(*arrays : Bytes) : Bytes
    WispLogger.logger.debug { "Concatenating #{arrays.size} byte arrays" }
    total_size = arrays.sum(&.size)
    result = Bytes.new(total_size)
    offset = 0
    arrays.each do |array|
      array.copy_to(result + offset)
      offset += array.size
    end
    result
  end

  def self.create_packet(packet_type : UInt8, stream_id : UInt32, payload : Bytes) : Bytes
    WispLogger.logger.debug { "Creating packet - Type: #{packet_type}, Stream ID: #{stream_id}, Payload size: #{payload.size}" }
    stream_id_bytes = slice_from_uint(stream_id, 4)
    packet_type_bytes = slice_from_uint(packet_type, 1)
    concat_bytes(packet_type_bytes, stream_id_bytes, payload)
  end
end

class Event
  @data : Bytes?
  getter type : String

  def initialize(@type : String, @data = nil)
    WispLogger.logger.debug { "Event created: #{@type}" }
  end

  def data
    @data
  end
end

class MessageEvent < Event
  def initialize(@data : Bytes)
    WispLogger.logger.debug { "MessageEvent created with #{@data.not_nil!.size} bytes" }
    super("message", @data)
  end

  def data : Bytes
    @data.not_nil!
  end
end


module EventEmitter
  @listeners = {} of String => Array(Proc(Event, Nil))

  def add_listener(event : String, &block : Event -> Nil)
    WispLogger.logger.debug { "Adding listener for event: #{event}" }
    @listeners[event] ||= [] of Proc(Event, Nil)
    @listeners[event] << block
  end

  def emit(event : String, data : Event)
    WispLogger.logger.debug { "Emitting event: #{event}" }
    @listeners[event]?.try &.each(&.call(data))
  end

  def remove_listener(event : String, &block : Event -> Nil)
    WispLogger.logger.debug { "Removing listener for event: #{event}" }
    @listeners[event]?.try &.delete(block)
  end
end

class Stream
  include EventEmitter

  enum BinaryType
    Blob
    ArrayBuffer
  end

  enum ReadyState
    Connecting = 0
    Open = 1
    Closing = 2
    Closed = 3
  end

  property binary_type : BinaryType = BinaryType::ArrayBuffer
  property open : Bool
  getter protocol : String = "binary"
  getter extensions : String = ""
  getter stream_id : UInt32
  getter hostname : String
  getter port : Int32

  @message_fragments = [] of Bytes
  @send_buffer = [] of Bytes
  @message_callback : Proc(Bytes, Nil)?
  @close_callback : Proc(UInt8, Nil)?

  def initialize(@hostname, @port, @websocket : HTTP::WebSocket, @buffer_size : Int32, @stream_id, @connection : Connection)
    WispLogger.logger.info { "Initializing Stream #{@stream_id} for #{@hostname}:#{@port}" }
    @open = false
  end

  def send(data : Bytes)
    WispLogger.logger.debug { "Stream #{@stream_id} sending #{data.size} bytes" }
    if @buffer_size > 0 || !@open
      packet = Wisp.create_packet(Wisp::PACKET_TYPES[:DATA], @stream_id, data)
      @websocket.send(packet)
      @buffer_size -= 1
      WispLogger.logger.debug { "Stream #{@stream_id} buffer size now: #{@buffer_size}" }
    else
      WispLogger.logger.debug { "Stream #{@stream_id} buffering data" }
      @send_buffer << data
    end
  end

  def continue_received(buffer_size : Int32)
    WispLogger.logger.debug { "Stream #{@stream_id} received continue with buffer size: #{buffer_size}" }
    @buffer_size = buffer_size
    while @buffer_size > 0 && !@send_buffer.empty?
      send(@send_buffer.shift)
    end
  end

  def close(reason : UInt8 = 0x01_u8)
    WispLogger.logger.info { "Closing Stream #{@stream_id} with reason: #{reason}" }
    return unless @open
    payload = Wisp.slice_from_uint(reason, 1)
    packet = Wisp.create_packet(Wisp::PACKET_TYPES[:CLOSE], @stream_id, payload)
    @websocket.send(packet)
    @open = false
    @connection.active_streams.delete(@stream_id)
    emit("close", Event.new("close"))
  end

  def on_message(&block : Bytes -> Nil)
    WispLogger.logger.debug { "Stream #{@stream_id} registered message callback" }
    @message_callback = block
  end

  def on_close(&block : UInt8 -> Nil)
    WispLogger.logger.debug { "Stream #{@stream_id} registered close callback" }
    @close_callback = block
  end

  def buffered_amount : Int32
    @send_buffer.sum(&.size)
  end

  def ready_state : ReadyState
    state = if !@connection.connected? && !@connection.connecting?
      ReadyState::Closed
    elsif !@connection.connected?
      ReadyState::Connecting
    elsif @open
      ReadyState::Open
    else
      ReadyState::Closed
    end
    WispLogger.logger.debug { "Stream #{@stream_id} ready state: #{state}" }
    state
  end

  def handle_message(payload : Bytes)
    WispLogger.logger.debug { "Stream #{@stream_id} handling message of #{payload.size} bytes" }
    event = MessageEvent.new(payload)
    emit("message", event)
    @message_callback.try &.call(payload)
  end

  private def handle_fragmented_message(fragment : Bytes, is_final : Bool)
    WispLogger.logger.debug { "Stream #{@stream_id} handling fragment (final: #{is_final})" }
    @message_fragments << fragment
    if is_final
      total_size = @message_fragments.sum(&.size)
      complete_message = Bytes.new(total_size)
      offset = 0
      @message_fragments.each do |frag|
        frag.copy_to(complete_message + offset)
        offset += frag.size
      end
      @message_fragments.clear
      handle_message(complete_message)
    end
  end

  def reconnect
    WispLogger.logger.info { "Stream #{@stream_id} initiating reconnection" }
    @connection.create_stream(@hostname, @port)
  end
end

class Connection
  include EventEmitter

  property ping_interval : Time::Span = 30.seconds
  property max_buffer_size : Int32?
  getter active_streams : Hash(UInt32, Stream)
  getter? connected : Bool
  getter? connecting : Bool

  @last_pong : Time = Time.utc
  @retry_count = 0
  @max_retries = 5
  @base_delay = 1.0
  @next_stream_id = 1_u32
  @heartbeat_channel = Channel(Nil).new
  @websocket : HTTP::WebSocket?
  @open_callback : Proc(Nil)?
  @close_callback : Proc(Nil)?
  @error_callback : Proc(Nil)?

  def initialize(@url : String)
    WispLogger.logger.info { "Initializing Connection to #{@url}" }
    @active_streams = {} of UInt32 => Stream
    @connected = false
    @connecting = false
    raise "Wisp endpoints must end with a trailing forward slash" unless @url.ends_with?("/")
    connect_ws_with_retry
  end

  def create_stream(hostname : String, port : Int32) : Stream
    stream_id = @next_stream_id
    @next_stream_id += 1

    WispLogger.logger.info { "Creating new stream #{stream_id} to #{hostname}:#{port}" }

    stream = Stream.new(hostname, port, @websocket.not_nil!, @max_buffer_size || 0, stream_id, self)
    stream.open = @connected

    type_bytes = Wisp.slice_from_uint(0x01_u8, 1)
    port_bytes = Wisp.slice_from_uint(port, 2)
    host_bytes = hostname.to_slice

    payload = Wisp.concat_bytes(type_bytes, port_bytes, host_bytes)
    packet = Wisp.create_packet(Wisp::PACKET_TYPES[:CONNECT], stream_id, payload)

    @active_streams[stream_id] = stream
    @websocket.not_nil!.send(packet)
    stream
  end

  def on_open(&block : -> Nil)
    WispLogger.logger.debug { "Registered open callback" }
    @open_callback = block
  end

  def on_close(&block : -> Nil)
    WispLogger.logger.debug { "Registered close callback" }
    @close_callback = block
  end

  def on_error(&block : -> Nil)
    WispLogger.logger.debug { "Registered error callback" }
    @error_callback = block
  end

  private def connect_ws
    WispLogger.logger.info { "Connecting WebSocket to #{@url}" }
    @websocket = HTTP::WebSocket.new(@url)
    @connecting = true

    @websocket.not_nil!.on_binary do |bytes|
      handle_packet(bytes)
    end

    @websocket.not_nil!.on_close do
      handle_close
    end

    spawn do
      begin
        @websocket.not_nil!.run
      rescue ex
        WispLogger.logger.error { "WebSocket error: #{ex.message}" }
        handle_error(ex)
      end
    end
  end

  private def connect_ws_with_retry
    WispLogger.logger.info { "Attempting connection (attempt #{@retry_count + 1}/#{@max_retries})" }
    connect_ws
    start_heartbeat
  rescue ex
    if @retry_count < @max_retries
      delay = @base_delay * (2 ** @retry_count)
      @retry_count += 1
      WispLogger.logger.warn { "Connection failed, retrying in #{delay} seconds" }
      sleep(delay.seconds)
      connect_ws_with_retry
    else
      WispLogger.logger.error { "Max retries exceeded" }
      raise ex
    end
  end

  private def start_heartbeat
    WispLogger.logger.debug { "Starting heartbeat monitor" }
    spawn do
      loop do
        select
        when @heartbeat_channel.receive
          break
        when timeout(ping_interval)
          if Time.utc - @last_pong > ping_interval * 2
            WispLogger.logger.warn { "Connection timeout detected" }
            handle_connection_timeout
          else
            send_ping
          end
        end
      end
    end
  end

  private def send_ping
    WispLogger.logger.debug { "Sending ping" }
    return unless @websocket
    ping_packet = Wisp.create_packet(Wisp::PACKET_TYPES[:PING], 0_u32, Bytes.new(0))
    @websocket.try &.send(ping_packet)
  end

  private def handle_connection_timeout
    WispLogger.logger.warn { "Handling connection timeout" }
    @websocket.try &.close
    handle_close
  end

  private def handle_close
    WispLogger.logger.info { "Handling connection close" }
    @heartbeat_channel.close
    @connected = false
    @connecting = false

    @active_streams.each do |stream_id, stream|
      WispLogger.logger.debug { "Closing stream #{stream_id}" }
      close_stream(stream, 0x03_u8)
    end

    emit("close", Event.new("close"))
    @close_callback.try &.call

    spawn { connect_ws_with_retry }
  end

  private def handle_error(ex : Exception)
    WispLogger.logger.error { "Connection error: #{ex.message}" }
    emit("error", Event.new("error"))
    @error_callback.try &.call
    handle_close
  end

  private def handle_packet(packet : Bytes)
    return if packet.size < 5

    packet_type = packet[0]
    stream_id = Wisp.uint_from_slice(packet[1, 4])
    payload = packet[5..]

    WispLogger.logger.debug { "Received packet - Type: #{packet_type}, Stream ID: #{stream_id}, Payload size: #{payload.size}" }

    stream = @active_streams[stream_id]?

    if !stream && stream_id != 0
      WispLogger.logger.warn { "Received packet for unknown stream: #{stream_id}" }
      return
    end

    case packet_type
    when Wisp::PACKET_TYPES[:DATA]
      WispLogger.logger.debug { "Processing DATA packet for stream #{stream_id}" }
      stream.try &.handle_message(payload)
    when Wisp::PACKET_TYPES[:CONTINUE]
      if stream_id == 0
        @max_buffer_size = Wisp.uint_from_slice(payload).to_i32
        WispLogger.logger.debug { "Updated max buffer size: #{@max_buffer_size}" }
      else
        WispLogger.logger.debug { "Processing CONTINUE packet for stream #{stream_id}" }
        stream.try &.continue_received(Wisp.uint_from_slice(payload).to_i32)
      end
    when Wisp::PACKET_TYPES[:CLOSE]
      WispLogger.logger.debug { "Processing CLOSE packet for stream #{stream_id}" }
      stream.try { |s| close_stream(s, payload[0]) }
    when Wisp::PACKET_TYPES[:PONG]
      WispLogger.logger.debug { "Received PONG" }
      @last_pong = Time.utc
    end

    if @connecting
      WispLogger.logger.info { "Connection established" }
      @connected = true
      @connecting = false
      emit("open", Event.new("open"))
      @open_callback.try &.call
    end
  end

  private def close_stream(stream : Stream, reason : UInt8)
    WispLogger.logger.info { "Closing stream #{stream.stream_id} with reason: #{reason}" }
    stream.open = false
    emit("close", Event.new("close"))
    stream.@close_callback.try &.call(reason)
    @active_streams.delete(stream.stream_id)
  end
end

class WispWebSocket
  include EventEmitter

  property binary_type : Stream::BinaryType = Stream::BinaryType::ArrayBuffer
  @stream : Stream?
  @protocols : Array(String)?

  def initialize(@url : String, @protocols : Array(String)? = nil)
    WispLogger.logger.info { "Initializing WispWebSocket for #{@url}" }
    uri = URI.parse(@url)
    path_parts = uri.path.not_nil!.split(":")
    @host = path_parts[0]
    @port = path_parts[1]?.try(&.to_i) || (uri.scheme == "wss" ? 443 : 80)
    @wisp_url = "#{uri.scheme}://#{uri.host}#{uri.port ? ":#{uri.port}" : ""}/wisp/"

    init_connection
  end

  def send(data : String | Bytes)
    WispLogger.logger.debug { "Sending data of size: #{data.is_a?(String) ? data.bytesize : data.size}" }
    raise "WebSocket is not connected" unless @stream
    payload = data.is_a?(String) ? data.to_slice : data
    @stream.not_nil!.send(payload)
  end

  def close(code = 1000, reason = "")
    WispLogger.logger.info { "Closing WebSocket with code: #{code}" }
    @stream.try &.close(0x02_u8)
  end

  def buffered_amount : Int32
    @stream.try(&.buffered_amount) || 0
  end

  def ready_state : Stream::ReadyState
    state = @stream.try(&.ready_state) || Stream::ReadyState::Connecting
    WispLogger.logger.debug { "Current ready state: #{state}" }
    state
  end

  private def init_connection
    WispLogger.logger.info { "Initializing connection to #{@wisp_url}" }
    @connection = Wisp.get_connection(@wisp_url)

    if !@connection.connected?
      WispLogger.logger.debug { "Connection not ready, waiting for open event" }
      @connection.add_listener("open") { init_stream }
    else
      init_stream
    end

    @connection.add_listener("close") { emit("close", Event.new("close")) }
    @connection.add_listener("error") { emit("error", Event.new("error")) }
  end

  private def init_stream
    return if @stream

    WispLogger.logger.info { "Initializing stream to #{@host}:#{@port}" }
    @stream = @connection.create_stream(@host, @port)
    @stream.not_nil!.binary_type = @binary_type

    @stream.not_nil!.add_listener("message") do |event|
      WispLogger.logger.debug { "Stream received message" }
      emit("message", event)
    end

    @stream.not_nil!.add_listener("close") do |event|
      WispLogger.logger.debug { "Stream closed" }
      emit("close", event)
    end

    emit("open", Event.new("open"))
  end
end
