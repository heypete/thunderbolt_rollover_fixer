"""
Copyright 2025 Pete Stephenson

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
"""

"""
A simple script to estimate the number of GPS week rollovers based on the GPS-UTC offset message transmitted by the GPS system. This may be useful for wholly-offline systems that cannot determine
the current date without GPS, and which need to calculate the number of rollovers to display the correct date and time. 
"""

def calculate_gps_week_rollovers(gps_utc_offset_seconds):
    """
    Calculate the number of GPS week rollovers as a function of the GPS-UTC time offset.

    Parameters:
    - gps_utc_offset_seconds (int): GPS-UTC time offset in seconds.

    Returns:
    - int: Estimated number of GPS week rollovers since the GPS epoch (January 6, 1980).
    """

    # Average number of weeks between the addition of a leap second,
    # given that 18 leap seconds have been added in the 2360 weeks
    # since the GPS epoch and March 28th, 2025 when I wrote this.
    # This can/should be updated periodically over time.
    leap_seconds_per_week = 2360 / 18 # 131.1111

    # Estimated current GPS week.
    estimated_gps_week = gps_utc_offset_seconds * leap_seconds_per_week

    # Each GPS rollover period is 1024 weeks long.
    weeks_per_gps_rollover = 1024

    # Calculate rollovers as an integer.
    rollovers = estimated_gps_week // weeks_per_gps_rollover

    return int(rollovers)


# Example usage
if __name__ == "__main__":
    # Current GPS-UTC offset (18 seconds as of now)
    gps_utc_offset = 18
    
    rollovers = calculate_gps_week_rollovers(gps_utc_offset)
    print(f"Estimated number of GPS week rollovers: {rollovers}")
