from HelperFunctionsTelemetry.GetDataTelemetry import getDataTables
tables = getDataTables("2023-02-24T10:00:00Z", "2023-02-24T10:00:01Z","oslo-gw1", "february", "egress_queue_info__0__cur_buffer_occupancy")
#Loop through all the tables and the rows and store them in a json structure based on weekday, hour, and minute
for table in tables:
    for row in table.records:
        print(row.values["_value"], row.values["_time"])
