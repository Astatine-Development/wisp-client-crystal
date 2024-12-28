require "json"
require "http/web_socket"

module Wisp
  @@connections = {} of String => Connection

  def self.get_connection(url : String) : Connection
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
    bytes = Bytes.new(size)
    size.times do |i|
      bytes[i] = ((int >> (8 * i)) & 0xFF).to_u8
    end
    bytes
  end

  def self.uint_from_slice(slice : Bytes) : UInt32
    case slice.size
    when 4 then slice.to_unsafe.as(UInt32*).value
    when 2 then slice.to_unsafe.as(UInt16*).value.to_u32
    when 1 then slice[0].to_u32
    else raise "Invalid slice length"
    end
  end

  def self.concat_bytes(*arrays : Bytes) : Bytes
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
    stream_id_bytes = slice_from_uint(stream_id, 4)
    packet_type_bytes = slice_from_uint(packet_type, 1)
    concat_bytes(packet_type_bytes, stream_id_bytes, payload)
  end
end

class Event
  @data : Bytes?
  getter type : String

  def initialize(@type : String, @data = nil)
  end

  def data
    @data
  end
end

class MessageEvent < Event
  def initialize(@data : Bytes)
    super("message", @data)
  end

  def data : Bytes
    @data.not_nil!
  end
end

module EventEmitter
  @listeners = {} of String => Array(Proc(Event, Nil))

  def add_listener(event : String, &block : Event -> Nil)
    @listeners[event] ||= [] of Proc(Event, Nil)
    @listeners[event] << block
  end

  def emit(event : String, data : Event)
    @listeners[event]?.try &.each(&.call(data))
  end

  def remove_listener(event : String, &block : Event -> Nil)
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
    @open = false
  end

  def send(data : Bytes)
    if @buffer_size > 0 || !@open
      packet = Wisp.create_packet(Wisp::PACKET_TYPES[:DATA], @stream_id, data)
      @websocket.send(packet)
      @buffer_size -= 1
    else
      @send_buffer << data
    end
  end

  def continue_received(buffer_size : Int32)
    @buffer_size = buffer_size
    while @buffer_size > 0 && !@send_buffer.empty?
      send(@send_buffer.shift)
    end
  end

  def close(reason : UInt8 = 0x01_u8)
    return unless @open
    payload = Wisp.slice_from_uint(reason, 1)
    packet = Wisp.create_packet(Wisp::PACKET_TYPES[:CLOSE], @stream_id, payload)
    @websocket.send(packet)
    @open = false
    @connection.active_streams.delete(@stream_id)
    emit("close", Event.new("close"))
  end

  def on_message(&block : Bytes -> Nil)
    @message_callback = block
  end

  def on_close(&block : UInt8 -> Nil)
    @close_callback = block
  end

  def buffered_amount : Int32
    @send_buffer.sum(&.size)
  end

  def ready_state : ReadyState
    if !@connection.connected? && !@connection.connecting?
      ReadyState::Closed
    elsif !@connection.connected?
      ReadyState::Connecting
    elsif @open
      ReadyState::Open
    else
      ReadyState::Closed
    end
  end

  def handle_message(payload : Bytes)
    event = MessageEvent.new(payload)
    emit("message", event)
    @message_callback.try &.call(payload)
  end

  private def handle_fragmented_message(fragment : Bytes, is_final : Bool)
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
    @active_streams = {} of UInt32 => Stream
    @connected = false
    @connecting = false
    raise "Wisp endpoints must end with a trailing forward slash" unless @url.ends_with?("/")
    connect_ws_with_retry
  end

  def create_stream(hostname : String, port : Int32) : Stream
    stream_id = @next_stream_id
    @next_stream_id += 1

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
    @open_callback = block
  end

  def on_close(&block : -> Nil)
    @close_callback = block
  end

  def on_error(&block : -> Nil)
    @error_callback = block
  end

  private def connect_ws
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
        handle_error(ex)
      end
    end
  end

  private def connect_ws_with_retry
    connect_ws
    start_heartbeat
  rescue ex
    if @retry_count < @max_retries
      delay = @base_delay * (2 ** @retry_count)
      @retry_count += 1
      sleep(delay.seconds)
      connect_ws_with_retry
    else
      raise ex
    end
  end

  private def start_heartbeat
    spawn do
      loop do
        select
        when @heartbeat_channel.receive
          break
        when timeout(ping_interval)
          if Time.utc - @last_pong > ping_interval * 2
            handle_connection_timeout
          else
            send_ping
          end
        end
      end
    end
  end

  private def send_ping
    return unless @websocket
    ping_packet = Wisp.create_packet(Wisp::PACKET_TYPES[:PING], 0_u32, Bytes.new(0))
    @websocket.try &.send(ping_packet)
  end

  private def handle_connection_timeout
    @websocket.try &.close
    handle_close
  end

  private def handle_close
    @heartbeat_channel.close
    @connected = false
    @connecting = false

    @active_streams.each do |stream_id, stream|
      close_stream(stream, 0x03_u8)
    end

    emit("close", Event.new("close"))
    @close_callback.try &.call

    spawn { connect_ws_with_retry }
  end

  private def handle_error(ex : Exception)
    emit("error", Event.new("error"))
    @error_callback.try &.call
    handle_close
  end

  private def handle_packet(packet : Bytes)
    return if packet.size < 5

    packet_type = packet[0]
    stream_id = Wisp.uint_from_slice(packet[1, 4])
    payload = packet[5..]
    stream = @active_streams[stream_id]?

    if !stream && stream_id != 0
      return
    end

    case packet_type
    when Wisp::PACKET_TYPES[:DATA]
      stream.try &.handle_message(payload)
    when Wisp::PACKET_TYPES[:CONTINUE]
      if stream_id == 0
        @max_buffer_size = Wisp.uint_from_slice(payload).to_i32
      else
        stream.try &.continue_received(Wisp.uint_from_slice(payload).to_i32)
      end
    when Wisp::PACKET_TYPES[:CLOSE]
      stream.try { |s| close_stream(s, payload[0]) }
    when Wisp::PACKET_TYPES[:PONG]
      @last_pong = Time.utc
    end

    if @connecting
      @connected = true
      @connecting = false
      emit("open", Event.new("open"))
      @open_callback.try &.call
    end
  end

  private def close_stream(stream : Stream, reason : UInt8)
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
    uri = URI.parse(@url)
    path_parts = uri.path.not_nil!.split(":")
    @host = path_parts[0]
    @port = path_parts[1]?.try(&.to_i) || (uri.scheme == "wss" ? 443 : 80)
    @wisp_url = "#{uri.scheme}://#{uri.host}#{uri.port ? ":#{uri.port}" : ""}/wisp/"

    init_connection
  end

  def send(data : String | Bytes)
    raise "WebSocket is not connected" unless @stream
    payload = data.is_a?(String) ? data.to_slice : data
    @stream.not_nil!.send(payload)
  end

  def close(code = 1000, reason = "")
    @stream.try &.close(0x02_u8)
  end

  def buffered_amount : Int32
    @stream.try(&.buffered_amount) || 0
  end

  def ready_state : Stream::ReadyState
    @stream.try(&.ready_state) || Stream::ReadyState::Connecting
  end

  private def init_connection
    @connection = Wisp.get_connection(@wisp_url)

    if !@connection.connected?
      @connection.add_listener("open") { init_stream }
    else
      init_stream
    end

    @connection.add_listener("close") { emit("close", Event.new("close")) }
    @connection.add_listener("error") { emit("error", Event.new("error")) }
  end

  private def init_stream
    return if @stream

    @stream = @connection.create_stream(@host, @port)
    @stream.not_nil!.binary_type = @binary_type

    @stream.not_nil!.add_listener("message") do |event|
      emit("message", event)
    end

    @stream.not_nil!.add_listener("close") do |event|
      emit("close", event)
    end

    emit("open", Event.new("open"))
  end
end
