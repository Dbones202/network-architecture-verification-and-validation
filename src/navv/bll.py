import json
import os
import pandas as pd

from navv.utilities import get_mac_vendor, timeit
from navv.validators import is_ipv4_address, is_ipv6_address


MAC_VENDORS_JSON_FILE = os.path.abspath(__file__ + "/../" + "data/mac-vendors.json")


def get_zeek_df(zeek_data, dns_data: dict):
    """Return a pandas dataframe of the conn.log data with its dns data."""
    if not isinstance(zeek_data, list):
        def generate_rows():
            for row in zeek_data:
                split_row = row.split("\t")
                if len(split_row) >= 3:
                    split_row.insert(1, dns_data.get(split_row[0], ""))
                    split_row.insert(3, dns_data.get(split_row[2], ""))
                yield split_row
        return pd.DataFrame(
            generate_rows(),
            columns=[
                "src_ip",
                "src_hostname",
                "dst_ip",
                "dst_hostname",
                "port",
                "proto",
                "conn",
                "src_mac",
                "dst_mac",
            ],
        )

    zeek_data = [row.split("\t") for row in zeek_data]
    # Insert dns data to zeek data
    for row in zeek_data:
        row.insert(1, dns_data.get(row[0], ""))
        row.insert(3, dns_data.get(row[2], ""))

    return pd.DataFrame(
        zeek_data,
        columns=[
            "src_ip",
            "src_hostname",
            "dst_ip",
            "dst_hostname",
            "port",
            "proto",
            "conn",
            "src_mac",
            "dst_mac",
        ],
    )



@timeit
def get_snmp_df(zeek_data):
    """Return a pandas dataframe of the snmp.log data."""
    if not isinstance(zeek_data, list):
        rows = (row.split("\t") for row in zeek_data)
        return pd.DataFrame(
            rows,
            columns=[
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "version",
                "community",
            ],
        )
    zeek_data = [row.split("\t") for row in zeek_data]
    return pd.DataFrame(
        zeek_data,
        columns=[
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "version",
            "community",
        ],
    )

@timeit
def get_mac_df(zeek_df: pd.DataFrame):
    smac_df = zeek_df[
        [
            "src_mac",
            "src_ip",
        ]
    ].reset_index(drop=True)

    dmac_df = zeek_df[
        [
            "dst_mac",
            "dst_ip",
        ]
    ].reset_index(drop=True)

    smac_df = smac_df.rename(columns={'src_mac': 'mac', 'src_ip': 'ip'})
    dmac_df = dmac_df.rename(columns={'dst_mac': 'mac', 'dst_ip': 'ip'})
    mac_df = pd.concat([smac_df, dmac_df], ignore_index=True)
    mac_df = mac_df.groupby('ip')['mac'].apply(lambda x: list(set(x))).reset_index(name='mac')

    def format_macs(macs):
        v_macs = [m for m in macs if m and m != '-']
        if not v_macs:
            return ""
        return ", ".join(str(item) for item in v_macs)

    mac_df["mac"] = mac_df["mac"].apply(format_macs)

    # Source Manufacturer column
    mac_vendors = {}
    with open(MAC_VENDORS_JSON_FILE, encoding="utf-8") as f:
        mac_vendors = json.load(f)
        
    def get_vendors(mac_val):
        if not mac_val: return "Unknown vendor"
        v_list = [get_mac_vendor(mac_vendors, m.strip()) for m in str(mac_val).split(',')]
        v_set = set(v for v in v_list if v != "Unknown vendor")
        if not v_set: return "Unknown vendor"
        return ', '.join(list(v_set))
        
    mac_df["vendor"] = mac_df["mac"].apply(get_vendors)

    return mac_df


@timeit
def get_http_df(zeek_data):
    """Return a pandas dataframe of the http.log data."""
    if not isinstance(zeek_data, list):
        rows = (row.split("\t") for row in zeek_data)
        return pd.DataFrame(
            rows,
            columns=[
                "src_ip",
                "dst_ip",
                "dst_port",
                "method",
                "host",
                "uri",
                "user_agent",
            ],
        )
    zeek_data = [row.split("\t") for row in zeek_data]
    return pd.DataFrame(
        zeek_data,
        columns=[
            "src_ip",
            "dst_ip",
            "dst_port",
            "method",
            "host",
            "uri",
            "user_agent",
        ],
    )


@timeit
def get_ssl_df(zeek_data):
    """Return a pandas dataframe of the ssl.log data."""
    if not isinstance(zeek_data, list):
        rows = (row.split("\t") for row in zeek_data)
        return pd.DataFrame(
            rows,
            columns=[
                "src_ip",
                "dst_ip",
                "dst_port",
                "version",
                "cipher",
                "curve",
                "server_name",
                "resumed",
            ],
        )
    zeek_data = [row.split("\t") for row in zeek_data]
    return pd.DataFrame(
        zeek_data,
        columns=[
            "src_ip",
            "dst_ip",
            "dst_port",
            "version",
            "cipher",
            "curve",
            "server_name",
            "resumed",
        ],
    )


@timeit
def get_generic_df(zeek_data, columns: list):
    """Return a pandas dataframe for generic logs."""
    if not isinstance(zeek_data, list):
        rows = (row.split("\t") for row in zeek_data)
        return pd.DataFrame(rows, columns=columns)
    zeek_data = [row.split("\t") for row in zeek_data]
    return pd.DataFrame(zeek_data, columns=columns)