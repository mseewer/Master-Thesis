from enum import Enum
from poc import choose_path, fetch_paths, Location, BR_addresses
import sys
import json
import datetime
import time


def save_down_segment(dst_IA, all_paths, location: Location):
    # only save down segement (as this part should be about to expire)
    new_data = {}
    for index in range(len(all_paths.get("paths", []))):
        br_addr = BR_addresses[location.name].value
        SCION_path = choose_path(dst_IA, all_paths, index, br_addr=br_addr)
        seg2len = SCION_path.Path.Seg2Len
        infofield = SCION_path.Path.InfoFields[-1]
        hopfields = SCION_path.Path.HopFields[-seg2len:]

        timestamp = infofield.Timestamp
        timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        new_data[timestamp_str] = {
                "HopFields": [bytes(hop).hex() for hop in hopfields],
                "InfoFields": bytes(infofield).hex(),
            }
    return new_data
   

def save_up_segment(dst_IA, all_paths, location: Location):
    # only save up segement
    new_data = {}
    for index in range(len(all_paths.get("paths", []))):
        br_addr = BR_addresses[location.name].value
        SCION_path = choose_path(dst_IA, all_paths, index, br_addr=br_addr)
        seg0len = SCION_path.Path.Seg0Len
        infofield = SCION_path.Path.InfoFields[0]
        hopfields = SCION_path.Path.HopFields[:seg0len]

        timestamp = infofield.Timestamp
        timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        new_data[timestamp_str] = {
                "HopFields": [bytes(hop).hex() for hop in hopfields],
                "InfoFields": bytes(infofield).hex(),
            }
    return new_data

def main(from_location: Location, to_location: Location):
    dstISD = 64
    dstAS = to_location.value
    dst_IA = f"{dstISD}-{dstAS}"

    while True:
        try:
            all_paths = fetch_paths(dst_IA)
            # SCION_path = choose_path(dst_IA, all_paths) #, sequence=seq)
            new_data = save_down_segment(dst_IA, all_paths, location=from_location)
            new_up_data = save_up_segment(dst_IA, all_paths, location=from_location)
        except Exception as e:
            print(e)
            print("Fetching path failed: ")
            # print stacktrace
            import traceback
            traceback.print_exc()
            time.sleep(10) # wait 10 seconds and try again
            print("Retrying...")
            continue

        file_name = f"path_seg_{from_location.name}-{to_location.name}.json"
        with open(file_name, mode="a+") as f:
            f.seek(0)
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                # file is empty
                data = {}
        old_len = len(data)
        for time_str in list(data.keys()):
            time_obj = datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            if time_obj < datetime.datetime.now() - datetime.timedelta(hours=12):
                del data[time_str]
        del_len = old_len - len(data)
        data.update(new_data)
        new_len = len(data) - old_len + del_len
        with open(file_name, mode="w") as f:
            json.dump(data, f, indent=4)

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{now}: Saved {new_len} new paths, removed {del_len} expired paths")
        
        file_up_name = f"path_seg_{from_location.name}-{to_location.name}_up.json"
        with open(file_up_name, mode="a+") as f:
            f.seek(0)
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                # file is empty
                data = {}
        old_len = len(data)
        for time_str in list(data.keys()):
            time_obj = datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            if time_obj < datetime.datetime.now() - datetime.timedelta(hours=12):
                del data[time_str]
        del_len = old_len - len(data)
        data.update(new_up_data)
        new_len = len(data) - old_len + del_len
        with open(file_up_name, mode="w") as f:
            json.dump(data, f, indent=4)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{now}: Saved {new_len} new up paths, removed {del_len} expired up paths")
        time.sleep(5*60)


if __name__ == "__main__":
    args = sys.argv
    if len(args) != 3:
        print("Usage: sudo python path_saver.py <from_location> <to_location>")
        sys.exit(1)
    from_location = args[1]
    to_location = args[2]
    if from_location not in Location.__members__:
        print("Invalid from location")
        print("Valid locations are: ", [loc.name for loc in Location])
        sys.exit(1)
    if to_location not in Location.__members__:
        print("Invalid to location")
        print("Valid locations are: ", [loc.name for loc in Location])
        sys.exit(1)
    from_loc = Location[from_location]
    to_loc = Location[to_location]
    main(from_loc, to_loc)