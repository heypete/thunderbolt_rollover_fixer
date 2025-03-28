"""
Copyright 2025 Pete Stephenson

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
"""

import sys
import serial
import struct
import argparse
import socket
import threading
from datetime import datetime, timedelta

# Constants
DLE = 0x10  # DLE byte
ETX = 0x03  # ETX byte
PRIMARY_TIMING_IDENTIFIER = [0x8F, 0xAB]  # Identifier for the primary timing packet
GPS_EPOCH = datetime(1980, 1, 6)  # GPS time begins on January 6, 1980
TCP_PORT_BINARY = 25000  # TCP server port for binary format

clients_binary = []  # List to keep track of binary stream clients

def calculate_gps_rollovers():
    # GPS epoch start time
    gps_epoch = datetime(1980, 1, 6, 0, 0, 0)

    # Get the current system time
    current_time = datetime.now()

    # Calculate the number of weeks since the GPS epoch
    elapsed_time = current_time - gps_epoch
    elapsed_weeks = elapsed_time.days // 7

    # Calculate the number of rollovers (1024 weeks per rollover)
    rollovers = elapsed_weeks // 1024

    return rollovers


def remove_stuffed_dle(data):
    """Remove stuffed DLE bytes from the data."""
    cleaned_data = bytearray()
    skip_next = False  # Flag to skip the next DLE byte

    for byte in data:
        if skip_next:
            # If we are skipping the current byte, reset the flag and continue
            skip_next = False
            continue

        if byte == DLE:  # Check if the current byte is DLE (0x10)
            # If the next byte is also DLE, skip the first and add the second
            skip_next = True
            cleaned_data.append(byte)
        else:
            # Add non-DLE bytes directly to cleaned_data
            cleaned_data.append(byte)

    # Add the final DLE byte if it was correctly handled
    if not skip_next and data[-1] == 0x10:  # Ensure last DLE isn't skipped
        cleaned_data.append(0x10)

    return cleaned_data


def bytes_to_hex_string(data):
    """Convert a bytearray to a space-separated hex string."""
    return " ".join(f"{byte:02X}" for byte in data)

def correct_gps_week(gps_week_number):
    """Apply rollover correction to the GPS week number."""
    corrected_week = gps_week_number
    if gps_week_number > 1024 and gps_week_number % 1024 < 936:
        corrected_week -= 1024
    return corrected_week

def apply_rollovers(gps_week_number, rollovers):
    """Apply the specified number of rollovers to the GPS week."""
    return gps_week_number + rollovers * 1024

def print_information(original_packet=None, cleaned_data=None, modified_packet=None, 
                      gps_week=None, corrected_week=None, final_gps_week=None, 
                      gps_seconds_of_week=None, gps_utc_offset=None, 
                      tbolt_time=None, gps_time=None, primary_packet_received=False):
    """Print all packet-related information to the terminal."""
    if primary_packet_received:
        print("\nPrimary Timing Packet Received!")

    if gps_week is not None:
        print(f"GPS Week (as reported by the Tbolt): {gps_week}")

    if corrected_week is not None:
        print(f"GPS Week (corrected for Tbolt internal rollover): {corrected_week}")

    if final_gps_week is not None:
        print(f"GPS Week (corrected for Tbolt rollover + GPS system rollover): {final_gps_week}")

    if gps_seconds_of_week is not None:
        print(f"GPS Seconds of the Week: {gps_seconds_of_week}")
    
    if gps_utc_offset is not None:
        print(f"GPS-UTC Offset (seconds): {gps_utc_offset}")

    if gps_time is not None:
        print(f"GPS Time:                {gps_time}")

    if tbolt_time is not None:
        print(f"Tbolt Time:              {tbolt_time}")
    else:
        print("Error: Tbolt time not available.")

    utc_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    print(f"UTC Time (system):       {utc_time}")

    if original_packet is not None:
        print(f"Original Packet (hex):   {bytes_to_hex_string(original_packet)}")

    if cleaned_data is not None:
        print(f"Cleaned Data (hex):         {bytes_to_hex_string(cleaned_data)}")

    if modified_packet is not None:
        print(f"Modified Packet (hex):   {bytes_to_hex_string(modified_packet)}")


def modify_primary_timing_packet(packet, final_gps_week, year, month, day, hour, minute, seconds):
    """Modify the primary timing packet with the final GPS week and calculated date/time."""
    # Extract the header and the payload
    header = packet[:3]  # DLE + Primary Timing Identifier (0x8F, 0xAB)
    payload = bytearray(packet[3:-2])  # Everything after the header and before the end sequence
    end_sequence = packet[-2:]  # Last part of the packet (DLE + ETX)

    # Update the GPS week number in the payload (bytes 5 and 6)
    gps_week_bytes = struct.pack(">H", final_gps_week)  # Convert GPS week to big-endian
    payload[4:6] = gps_week_bytes  # Replace bytes 5 and 6 in the payload (GPS week)

    # Update the seconds, minutes, hours, day, month, and year in the payload
    payload[9] = seconds  # Byte 10: Seconds (0-59)
    payload[10] = minute  # Byte 11: Minutes (0-59)
    payload[11] = hour  # Byte 12: Hours (0-23)
    payload[12] = day  # Byte 13: Day of the month (1-31)
    payload[13] = month  # Byte 14: Month (1-12)
    payload[14:16] = struct.pack(">H", year)  # Bytes 15 and 16: Year (four-digit UINT16)

    # Perform DLE stuffing: add an additional DLE before each existing DLE in the payload
    stuffed_payload = bytearray()
    for byte in payload:
        stuffed_payload.append(byte)
        if byte == DLE:  # Check if the byte is DLE (0x10)
            stuffed_payload.append(DLE)  # Insert an additional DLE byte

    # Rebuild the packet
    new_packet = header + stuffed_payload + end_sequence

    return new_packet


def broadcast_data(data):
    """Send raw serial data to all connected TCP clients."""
    # Send data to all connected TCP clients
    for client_socket in clients_binary:
        try:
            client_socket.sendall(data)  # Send data to the client
        except socket.error:
            # If sending fails, remove the client from the list
            clients_binary.remove(client_socket)
            print(f"Client {client_socket.getpeername()} disconnected and removed.")


def extract_date_and_time(payload, final_gps_week):
    """Calculate the current date and time using the final GPS week and the payload."""
    # Extract GPS seconds of the week (bytes 1-4) as a UINT32
    gps_seconds_of_week = struct.unpack(">I", payload[0:4])[0]

    # Extract GPS-UTC offset (bytes 7-8) as a SINT16
    gps_utc_offset = struct.unpack(">h", payload[6:8])[0]

    # Calculate total GPS time using the corrected GPS week
    total_gps_seconds = final_gps_week * 7 * 24 * 60 * 60 + gps_seconds_of_week  # Final GPS week in seconds
    gps_time = GPS_EPOCH + timedelta(seconds=total_gps_seconds)  # GPS time doesn't include UTC offset

    # Calculate Tbolt time (GPS adjusted for UTC offset)
    tbolt_time = gps_time - timedelta(seconds=gps_utc_offset)

    # Extract year, month, day, hour, minute, and seconds from Tbolt time
    year = tbolt_time.year  # UINT16
    month = tbolt_time.month  # UINT8
    day = tbolt_time.day  # UINT8
    hour = tbolt_time.hour  # UINT8
    minute = tbolt_time.minute  # UINT8
    seconds = tbolt_time.second  # UINT8

    # Return Tbolt time, GPS time, and GPS-UTC offset
    return year, month, day, hour, minute, seconds, gps_utc_offset, gps_time

def process_packet(packet, rollovers):
    """Process the complete packet. Modify and send the primary timing packet."""
    # Extract the data section (everything after the initial DLE and before the end sequence)
    data_section = packet[1:-2]  # Remove the start DLE byte and the end sequence
    cleaned_data = remove_stuffed_dle(data_section)

    if cleaned_data[:2] == bytearray(PRIMARY_TIMING_IDENTIFIER):
        primary_packet_received = True

        payload = cleaned_data[2:]  # Skip the first 2 bytes (primary timing identifier)

        gps_week_bytes = payload[4:6]
        if len(gps_week_bytes) == 2:
            original_gps_week = struct.unpack(">H", gps_week_bytes)[0]
            corrected_week = correct_gps_week(original_gps_week)
            final_gps_week = apply_rollovers(corrected_week, rollovers)

            # Calculate GPS time, GPS-UTC offset, and Tbolt time
            year, month, day, hour, minute, seconds, gps_utc_offset, gps_time = extract_date_and_time(payload, final_gps_week)
            tbolt_time = f"{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{seconds:02}"
            gps_time_formatted = gps_time.strftime("%Y-%m-%dT%H:%M:%S")

            # Modify the packet with the corrected GPS week and calculated date/time
            modified_packet = modify_primary_timing_packet(packet, final_gps_week, year, month, day, hour, minute, seconds)

            # Print useful information
            print_information(
                original_packet=packet,
                cleaned_data=cleaned_data,
                modified_packet=modified_packet,
                gps_week=original_gps_week,
                corrected_week=corrected_week,
                final_gps_week=final_gps_week,
                gps_seconds_of_week=struct.unpack(">I", payload[0:4])[0],
                gps_utc_offset=gps_utc_offset,
                tbolt_time=tbolt_time,
                gps_time=gps_time_formatted,
                primary_packet_received=primary_packet_received
            )

            # Send the modified packet
            broadcast_data(modified_packet)
        else:
            print("Error: GPS week bytes could not be extracted (packet too short).")
    else:
        # If the packet is not the primary timing packet, send it unmodified
        broadcast_data(packet)

def start_tcp_server(port, ser):
    """Start a TCP server to handle clients and forward their valid data to the serial port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)  # Allow up to 5 pending connections
    print(f"TCP server listening on port {port}...")

    try:
        while True:
            client_socket, addr = server.accept()
            client_handler = threading.Thread(target=handle_client, args=(client_socket, ser))
            client_handler.daemon = True
            client_handler.start()
    except KeyboardInterrupt:
        print(f"\nShutting down TCP server on port {port}.")
    finally:
        server.close()

def handle_client(client_socket, ser):
    """Handle client connections by adding them to the client list and relaying incoming data."""
    try:
        print(f"Client connected: {client_socket.getpeername()}")
        clients_binary.append(client_socket)
        while True:
            # Relay incoming TCP data to the serial port
            tcp_data = client_socket.recv(1024)
            if tcp_data:
                ser.write(tcp_data)
    except socket.error as e:
        print(f"Client disconnected: {e}")
    finally:
        if client_socket in clients_binary:
            clients_binary.remove(client_socket)
        client_socket.close()



def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Stream raw serial data to TCP and relay valid TCP data to the serial port.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument(
        "port",
        nargs="?",
        default="COM1",
        help="The serial port to listen on."
    )
    parser.add_argument(
        "--baudrate", "-b",
        type=int,
        default=9600,
        help="Baudrate for the serial port."
    )
    parser.add_argument(
        "--rollovers", "-r",
        type=int,
        default=calculate_gps_rollovers(),
        help="The number of GPS week rollovers since the GPS epoch.).",
    )
    parser.add_argument(
        "--tcp-port", "-tp",
        type=int,
        default=25000,
        help="The TCP port to use for the server.",
    )
    args = parser.parse_args()
   
    port = args.port
    baudrate = args.baudrate
    rollovers = args.rollovers
    tcp_port = args.tcp_port  # Get the TCP port from command-line arguments

    try:
        # Open the primary serial port (e.g., COM1 or /dev/ttyS1)
        ser = serial.Serial(port, baudrate=baudrate, timeout=1)
        print(f"Listening on serial port {port} with baudrate {baudrate}...")

        # Start the TCP server in a separate thread using the specified or default TCP port
        tcp_server_thread = threading.Thread(target=start_tcp_server, args=(tcp_port, ser))
        tcp_server_thread.daemon = True
        tcp_server_thread.start()

        # Process and broadcast valid data packets
        packet = bytearray()
        in_packet = False
        dle_count = 0

        while True:
            byte = ser.read(1)
            if byte:
                byte_value = byte[0]
                packet.append(byte_value)

                if byte_value == DLE:
                    if not in_packet:
                        in_packet = True
                        packet = bytearray([byte_value])  # Start a new packet
                    else:
                        dle_count += 1
                elif in_packet:
                    if byte_value == ETX and dle_count % 2 == 1:
                        # Process valid packets
                        process_packet(packet, rollovers)
                        in_packet = False
                        dle_count = 0
                    elif byte_value != DLE:
                        dle_count = 0  # Reset DLE count for non-DLE bytes
    except serial.SerialException as e:
        print(f"Serial Error: {e}")
    except KeyboardInterrupt:
        print("\nExiting program.")
    finally:
        if 'ser' in locals() and ser.is_open:
            ser.close()

if __name__ == "__main__":
    main()
