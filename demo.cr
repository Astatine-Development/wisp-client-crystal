require "./client.cr"

# Create a Wisp connection
connection = Wisp.get_connection("wss://wisp.mercurywork.shop/wisp/") #replace with your wisp server of choice

# Set up connection event handlers
connection.add_listener("open") do |_event|
  puts "Connected to Wisp server"

  # Create a stream to example.com
  stream = connection.create_stream("example.com", 80)

  # Set up stream event handlers with the new event system
  stream.add_listener("message") do |event|
    if event.is_a?(MessageEvent)
      message = String.new(event.data.as(Bytes))
      puts "Received: #{message}"
    end
  end

  stream.add_listener("close") do |event|
    puts "Stream closed"
  end

  # Send HTTP GET request
  http_request = [
    "GET / HTTP/1.1",
    "Host: example.com",
    "Connection: close", #set to keep-alive if you want to maintain the connection
    "User-Agent: Wisp/1.0",
    "",
    ""
  ].join("\r\n")

  stream.send(http_request.to_slice)

  # Monitor buffered amount
  puts "Buffered amount: #{stream.buffered_amount}"
  puts "Ready state: #{stream.ready_state}"
end

connection.add_listener("close") do |_event|
  puts "Disconnected from Wisp server"
end

connection.add_listener("error") do |_event|
  puts "Error occurred with Wisp connection"
end

# Keep the program running
sleep
