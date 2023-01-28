from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

bucket = "a62181947a589d5f"

client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7")

write_api = client.write_api(write_options=SYNCHRONOUS)
query_api = client.query_api()

p = Point("my_measurement2").tag("location", "Oslo").field("temperature", 5)

write_api.write(bucket=bucket, record=p)

## using Table structure
tables = query_api.query('from(bucket:"test") |> range(start: -10m)')

for table in tables:
    print("Table", table)
    for row in table.records:
        print (row.values)


## using csv library
csv_result = query_api.query_csv('from(bucket:"test") |> range(start: -10m)')
val_count = 0
for row in csv_result:
    for cell in row:
        val_count += 1