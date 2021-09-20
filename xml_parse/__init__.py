import pandas as pd
import numpy as np
import logging
import re
from jnpr.junos.exception import RpcError


def parse_xml(root, df_list=[]):
    columns = [root[n].tag for n in range(len(root))]
    value = [root[n].text for n in range(len(root))]
    attrib_dict_list = [root[n].attrib for n in range(len(root))]
    attrib_columns = []
    attrib_values = []
    if len(attrib_dict_list):
        for n, i in enumerate(attrib_dict_list):
            if i.keys():
                key = i.keys()
                attrib_columns.append(root[n].tag + '_' + key[0])
                attrib_values.append(i[key[0]])
        columns.extend(attrib_columns)
        value.extend(attrib_values)
    df = pd.DataFrame(columns=columns, data=np.array([value]))
    if not df.dropna(axis=1).empty:
        df.dropna(inplace=True, axis=1)
        df_list.append(df)
    child_list = [len(j) for j in root]
    for index, n in enumerate(child_list):
        if n > 0:
            parse_xml(root[index], df_list=df_list)
    return df_list


def parse_xml_inventory(root, fpc, mic, pic, df_list=[]):
    columns = [root[n].tag for n in range(len(root))]
    value = [root[n].text for n in range(len(root))]
    attrib_dict_list = [root[n].attrib for n in range(len(root))]
    attrib_columns = []
    attrib_values = []
    if len(attrib_dict_list):
        for n, i in enumerate(attrib_dict_list):
            if i.keys():
                key = i.keys()
                attrib_columns.append(root[n].tag + '_' + key[0])
                attrib_values.append(i[key[0]])
        columns.extend(attrib_columns)
        value.extend(attrib_values)
    df = pd.DataFrame(columns=columns, data=np.array([value]))
    if not df.dropna(axis=1).empty:
        df.dropna(inplace=True, axis=1)
        if 'name' in df.columns:
            if 'Xcvr' in df['name'].item():
                try:
                    df['name'] = re.sub("[^0-9]", "", fpc) + '/' + re.sub("[^0-9]", "", pic) + '/' + \
                                 df['name'].str.replace(' ', '').str.replace(r'[A-z]', '')
                except:
                    df = pd.DataFrame()
            elif 'MIC' in df['name'].item():
                mic = df['name'].item()
                df['name'] = fpc + ' ' + df['name']
            elif 'CPU' in df['name'].item():
                df['name'] = fpc + ' ' + df['name']
            elif 'PIC' in df['name'].item() and mic:
                pic = df['name'].item()
                df['name'] = fpc + ' ' + mic + ' ' + df['name']
            elif 'PIC' in df['name'].item():
                pic = df['name'].item()
                df['name'] = fpc + ' ' + df['name']
            elif 'FPC' in df['name'].item():
                fpc = df['name'].item()
        df_list.append(df)
    child_list = [len(j) for j in root]
    for index, n in enumerate(child_list):
        if n > 0:
            parse_xml_inventory(root=root[index], fpc=fpc, mic=mic, pic=pic, df_list=df_list)
    return df_list


def parse_xml_cos(root, df_list=[]):
    columns = [root[n].tag for n in range(len(root))]
    value = [root[n].text for n in range(len(root))]
    attrib_dict_list = [root[n].attrib for n in range(len(root))]
    attrib_columns = []
    attrib_values = []
    if len(attrib_dict_list):
        for n, i in enumerate(attrib_dict_list):
            if i.keys():
                key = i.keys()
                attrib_columns.append(root[n].tag + '_' + key[0])
                attrib_values.append(i[key[0]])
        columns.extend(attrib_columns)
        value.extend(attrib_values)
    df = pd.DataFrame(columns=columns, data=np.array([value]))
    if not df.dropna(axis=1).empty:
        df.dropna(inplace=True, axis=1)
        df_list.append(df)
    child_list = [len(j) for idx, j in enumerate(root) if root[idx].tag != 'i-logical-map']
    for index, n in enumerate(child_list):
        if n > 0:
            parse_xml_cos(root=root[index], df_list=df_list)
    return df_list


def parse_xml_coredumps(root, re, df_list=[]):
    columns = [root[n].tag for n in range(len(root))]
    value = [root[n].text for n in range(len(root))]
    attrib_dict_list = [root[n].attrib for n in range(len(root))]
    attrib_columns = []
    attrib_values = []
    if len(attrib_dict_list):
        for n, i in enumerate(attrib_dict_list):
            if i.keys():
                key = i.keys()
                attrib_columns.append(root[n].tag + '_' + key[0])
                attrib_values.append(i[key[0]])
        columns.extend(attrib_columns)
        value.extend(attrib_values)
    df = pd.DataFrame(columns=columns, data=np.array([value]))
    if len(df.columns) > len(set(df.columns)):
        counter = 0
        new_columns = []
        for n, i in enumerate(df.columns):
            if list(df.columns).count(df.columns[n]) > 1:
                new_columns.append(i + '_' + str(counter))
                counter += 1
            else:
                new_columns.append(i)
        df.columns = new_columns
    df['re-name'] = re
    if not df.dropna(axis=1).empty:
        df.dropna(inplace=True, axis=1)
        try:
            df = df[df['file-name'].notnull()]
            df_list.append(df)
        except:
            df_list.append(pd.DataFrame())
    child_list = [len(j) for j in root]
    for index, n in enumerate(child_list):
        if n > 0:
            parse_xml_coredumps(root=root[index], re=re, df_list=df_list)
    return df_list


def parse_xml_storage(root, re, df_list=[]):
    columns = [root[n].tag for n in range(len(root))]
    value = [root[n].text for n in range(len(root))]
    attrib_dict_list = [root[n].attrib for n in range(len(root))]
    attrib_columns = []
    attrib_values = []
    if len(attrib_dict_list):
        for n, i in enumerate(attrib_dict_list):
            if i.keys():
                key = i.keys()
                attrib_columns.append(root[n].tag + '_' + key[0])
                attrib_values.append(i[key[0]])
        columns.extend(attrib_columns)
        value.extend(attrib_values)
    df = pd.DataFrame(columns=columns, data=np.array([value]))
    if len(df.columns) > len(set(df.columns)):
        counter = 0
        new_columns = []
        for n, i in enumerate(df.columns):
            if list(df.columns).count(df.columns[n]) > 1:
                new_columns.append(i + '_' + str(counter))
                counter += 1
            else:
                new_columns.append(i)
        df.columns = new_columns
    df['re-name'] = re
    if not df.dropna(axis=1).empty:
        df.dropna(inplace=True, axis=1)
        df_list.append(df)
    child_list = [len(j) for j in root]
    for index, n in enumerate(child_list):
        if n > 0:
            parse_xml_storage(root=root[index], re=re, df_list=df_list)
    return df_list


def parse_xml_w_duplicates(root, df_list=[]):
    columns = [root[n].tag for n in range(len(root))]
    value = [root[n].text for n in range(len(root))]
    attrib_dict_list = [root[n].attrib for n in range(len(root))]
    attrib_columns = []
    attrib_values = []
    if len(attrib_dict_list):
        for n, i in enumerate(attrib_dict_list):
            if i.keys():
                key = i.keys()
                attrib_columns.append(root[n].tag + '_' + key[0])
                attrib_values.append(i[key[0]])
        columns.extend(attrib_columns)
        value.extend(attrib_values)
    df = pd.DataFrame(columns=columns, data=np.array([value]))
    if len(df.columns) > len(set(df.columns)):
        counter = 0
        new_columns = []
        for n, i in enumerate(df.columns):
            if list(df.columns).count(df.columns[n]) > 1:
                new_columns.append(i + '_' + str(counter))
                counter += 1
            else:
                new_columns.append(i)
        df.columns = new_columns
    if not df.dropna(axis=1).empty:
        df.dropna(inplace=True, axis=1)
        df_list.append(df)
    child_list = [len(j) for j in root]
    for index, n in enumerate(child_list):
        if n > 0:
            parse_xml_w_duplicates(root[index], df_list=df_list)
    return df_list

def parse_xml_uptime(root, parent_type, df_list=[]):
    columns = [root[n].tag for n in range(len(root))]
    value = [root[n].text for n in range(len(root))]
    attrib_dict_list = [root[n].attrib for n in range(len(root))]
    attrib_columns = []
    attrib_values = []
    if len(attrib_dict_list):
        for n, i in enumerate(attrib_dict_list):
            if i.keys():
                key = i.keys()
                attrib_columns.append(root[n].tag + '_' + key[0])
                attrib_values.append(i[key[0]])
        columns.extend(attrib_columns)
        value.extend(attrib_values)
    df = pd.DataFrame(columns=columns, data=np.array([value]))
    df['type'] = parent_type
    if not df.dropna(axis=1).empty:
        df.dropna(inplace=True, axis=1)
        df_list.append(df)
    child_list = [len(j) for j in root]
    for index, n in enumerate(child_list):
        if n > 0:
            parent_type = root[index].tag
            parse_xml_uptime(root[index], parent_type=parent_type, df_list=df_list)
    return df_list

def ex_get_output(dev, output_dict_xml):
    output_dict_xml['inventory_xml'] = dev.rpc.get_chassis_inventory()
    output_dict_xml['re_xml'] = dev.rpc.get_route_engine_information()
    output_dict_xml['fpc_xml'] = dev.rpc.get_fpc_information()
    output_dict_xml['fpc_detail_xml'] = dev.rpc.get_fpc_information(detail=True)
    output_dict_xml['alarm_xml'] = dev.rpc.get_system_alarm_information()
    output_dict_xml['environment_xml'] = dev.rpc.get_environment_information()
    output_dict_xml['interface_xml'] = dev.rpc.get_interface_information(level='media', dev_timeout=60)
    output_dict_xml['optics_xml'] = dev.rpc.get_interface_optics_diagnostics_information()
    output_dict_xml['uptime'] = dev.rpc.get_system_uptime_information()
    try:
        output_dict_xml['core_dumps_xml'] = dev.rpc.cli('show system core-dumps all-members', format="xml")
    except RpcError:
        output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()

    try:
        output_dict_xml['storage_xml'] = dev.rpc.cli('show system storage all-members', format="xml")
    except RpcError:
        output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()

    try:
        output_dict_xml['cos_xml'] = dev.rpc.get_cos_interface_map_information(dev_timeout=60)
    except RpcError:
        output_dict_xml['cos_xml'] = None

    try:
        output_dict_xml['resource_monitor_xml'] = dev.rpc.get_resource_monitor_summary_fpc_information()
    except RpcError:
        output_dict_xml['resource_monitor_xml'] = None

    return output_dict_xml


def mx104_get_output(dev, output_dict_xml):
    output_dict_xml['inventory_xml'] = dev.rpc.get_chassis_inventory()
    output_dict_xml['re_xml'] = dev.rpc.get_route_engine_information()
    output_dict_xml['fpc_xml'] = dev.rpc.get_fpc_information()
    output_dict_xml['fpc_detail_xml'] = dev.rpc.get_fpc_information(detail=True)
    output_dict_xml['alarm_xml'] = dev.rpc.get_system_alarm_information()
    output_dict_xml['environment_xml'] = dev.rpc.get_environment_information()
    output_dict_xml['interface_xml'] = dev.rpc.get_interface_information(level='media', dev_timeout=60)
    output_dict_xml['optics_xml'] = dev.rpc.get_interface_optics_diagnostics_information()
    output_dict_xml['uptime'] = dev.rpc.get_system_uptime_information()
    if dev.facts['2RE']:
        try:
            output_dict_xml['core_dumps_xml'] = dev.rpc.cli('show system core-dumps routing-engine both', format="xml")
        except RpcError:
            output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()
    else:
        output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()
    if dev.facts['2RE']:
        try:
            output_dict_xml['storage_xml'] = dev.rpc.cli('show system storage invoke-on all-routing-engines',
                                                         format="xml")
        except RpcError:
            output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()
    else:
        output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()
    try:
        output_dict_xml['cos_xml'] = dev.rpc.get_cos_interface_map_information(dev_timeout=60)
    except RpcError:
        output_dict_xml['cos_xml'] = None
    try:
        output_dict_xml['snapshot_xml'] = dev.rpc.get_snapshot_information()
    except RpcError:
        output_dict_xml['snapshot_xml'] = None
    output_dict_xml['network_services_xml'] = dev.rpc.network_services()
    output_dict_xml['resource_monitor_xml'] = dev.rpc.get_resource_monitor_summary_fpc_information()

    return output_dict_xml


def mx_small_get_output(dev, output_dict_xml):
    output_dict_xml['inventory_xml'] = dev.rpc.get_chassis_inventory()
    output_dict_xml['re_xml'] = dev.rpc.get_route_engine_information()
    output_dict_xml['fpc_xml'] = dev.rpc.get_fpc_information()
    output_dict_xml['fpc_detail_xml'] = dev.rpc.get_fpc_information(detail=True)
    output_dict_xml['alarm_xml'] = dev.rpc.get_system_alarm_information()
    output_dict_xml['environment_xml'] = dev.rpc.get_environment_information()
    output_dict_xml['interface_xml'] = dev.rpc.get_interface_information(level='media', dev_timeout=60)
    output_dict_xml['optics_xml'] = dev.rpc.get_interface_optics_diagnostics_information()
    output_dict_xml['uptime'] = dev.rpc.get_system_uptime_information()
    try:
        output_dict_xml['snapshot_xml'] = dev.rpc.get_snapshot_information()
    except RpcError:
        output_dict_xml['snapshot_xml'] = None
    output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()
    output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()
    try:
        output_dict_xml['cos_xml'] = dev.rpc.get_cos_interface_map_information(dev_timeout=60)
    except RpcError:
        output_dict_xml['cos_xml'] = None
    output_dict_xml['network_services_xml'] = dev.rpc.network_services()
    output_dict_xml['resource_monitor_xml'] = dev.rpc.get_resource_monitor_summary_fpc_information()

    return output_dict_xml


def mx_classical_get_output(dev, output_dict_xml):
    output_dict_xml['inventory_xml'] = dev.rpc.get_chassis_inventory()
    output_dict_xml['re_xml'] = dev.rpc.get_route_engine_information()
    output_dict_xml['fpc_xml'] = dev.rpc.get_fpc_information()
    output_dict_xml['fpc_detail_xml'] = dev.rpc.get_fpc_information(detail=True)
    output_dict_xml['alarm_xml'] = dev.rpc.get_system_alarm_information()
    output_dict_xml['environment_xml'] = dev.rpc.get_environment_information()
    output_dict_xml['interface_xml'] = dev.rpc.get_interface_information(level='media', dev_timeout=60)
    output_dict_xml['optics_xml'] = dev.rpc.get_interface_optics_diagnostics_information()
    output_dict_xml['uptime'] = dev.rpc.get_system_uptime_information()
    output_dict_xml['power_xml'] = dev.rpc.get_power_usage_information()
    output_dict_xml['snapshot_xml'] = dev.rpc.get_snapshot_information()
    if dev.facts['2RE']:
        try:
            output_dict_xml['core_dumps_xml'] = dev.rpc.cli('show system core-dumps routing-engine both', format="xml")
        except RpcError:
            output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()
    else:
        output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()

    if dev.facts['2RE']:
        try:
            output_dict_xml['storage_xml'] = dev.rpc.cli('show system storage invoke-on all-routing-engines',
                                                         format="xml")
        except RpcError:
            output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()
    else:
        output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()

    if dev.facts['2RE'] and (
            dev.facts['RE0']['model'] == 'RE-S-2X00x6' or dev.facts['RE1']['model'] == 'RE-S-2X00x6'):
        output_dict_xml['vmhost_version_xml'] = dev.rpc.cli('show vmhost version routing-engine both', format="xml")

    try:
        output_dict_xml['cos_xml'] = dev.rpc.get_cos_interface_map_information(dev_timeout=60)
    except RpcError:
        output_dict_xml['cos_xml'] = None

    output_dict_xml['network_services_xml'] = dev.rpc.network_services()

    try:
        output_dict_xml['resource_monitor_xml'] = dev.rpc.get_resource_monitor_summary_fpc_information()
    except RpcError:
        output_dict_xml['cos_xml'] = None

    return output_dict_xml


def tseries_get_output(dev, output_dict_xml):
    output_dict_xml['inventory_xml'] = dev.rpc.get_chassis_inventory()
    output_dict_xml['re_xml'] = dev.rpc.get_route_engine_information()
    output_dict_xml['fpc_xml'] = dev.rpc.get_fpc_information()
    output_dict_xml['fpc_detail_xml'] = dev.rpc.get_fpc_information(detail=True)
    output_dict_xml['alarm_xml'] = dev.rpc.get_system_alarm_information()
    output_dict_xml['environment_xml'] = dev.rpc.get_environment_information()
    output_dict_xml['interface_xml'] = dev.rpc.get_interface_information(level='media', dev_timeout=60)
    output_dict_xml['optics_xml'] = dev.rpc.get_interface_optics_diagnostics_information()
    output_dict_xml['uptime'] = dev.rpc.get_system_uptime_information()
    output_dict_xml['snapshot_xml'] = dev.rpc.get_snapshot_information()
    if dev.facts['2RE']:
        try:
            output_dict_xml['core_dumps_xml'] = dev.rpc.cli('show system core-dumps routing-engine both', format="xml")
        except RpcError:
            output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()
    else:
        output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()
    if dev.facts['2RE']:
        try:
            output_dict_xml['storage_xml'] = dev.rpc.cli('show system storage invoke-on all-routing-engines',
                                                         format="xml")
        except RpcError:
            output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()
    else:
        output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()
    try:
        output_dict_xml['cos_xml'] = dev.rpc.get_cos_interface_map_information(dev_timeout=60)
    except RpcError:
        output_dict_xml['cos_xml'] = None

    return output_dict_xml


def qfx10002_get_output(dev, output_dict_xml):
    output_dict_xml['inventory_xml'] = dev.rpc.get_chassis_inventory()
    output_dict_xml['re_xml'] = dev.rpc.get_route_engine_information()
    output_dict_xml['fpc_xml'] = dev.rpc.get_fpc_information()
    output_dict_xml['fpc_detail_xml'] = dev.rpc.get_fpc_information(detail=True)
    output_dict_xml['alarm_xml'] = dev.rpc.get_system_alarm_information()
    output_dict_xml['environment_xml'] = dev.rpc.get_environment_information()
    output_dict_xml['interface_xml'] = dev.rpc.get_interface_information(level='media', dev_timeout=60)
    output_dict_xml['optics_xml'] = dev.rpc.get_interface_optics_diagnostics_information()
    output_dict_xml['uptime'] = dev.rpc.get_system_uptime_information()
    output_dict_xml['snapshot_xml'] = dev.rpc.get_snapshot_information()
    output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()
    output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()
    try:
        output_dict_xml['cos_xml'] = dev.rpc.get_cos_interface_map_information(dev_timeout=60)
    except RpcError:
        output_dict_xml['cos_xml'] = None
    output_dict_xml['resource_monitor_xml'] = dev.rpc.get_resource_monitor_summary_fpc_information()

    return output_dict_xml


def qfx10k_get_output(dev, output_dict_xml):
    output_dict_xml['inventory_xml'] = dev.rpc.get_chassis_inventory()
    output_dict_xml['re_xml'] = dev.rpc.get_route_engine_information()
    output_dict_xml['fpc_xml'] = dev.rpc.get_fpc_information()
    output_dict_xml['fpc_detail_xml'] = dev.rpc.get_fpc_information(detail=True)
    output_dict_xml['alarm_xml'] = dev.rpc.get_system_alarm_information()
    output_dict_xml['environment_xml'] = dev.rpc.get_environment_information()
    output_dict_xml['interface_xml'] = dev.rpc.get_interface_information(level='media', dev_timeout=60)
    output_dict_xml['optics_xml'] = dev.rpc.get_interface_optics_diagnostics_information()
    output_dict_xml['uptime'] = dev.rpc.get_system_uptime_information()
    output_dict_xml['power_xml'] = dev.rpc.get_power_usage_information()
    output_dict_xml['snapshot_xml'] = dev.rpc.get_snapshot_information()
    if dev.facts['2RE']:
        try:
            output_dict_xml['core_dumps_xml'] = dev.rpc.cli('show system core-dumps routing-engine both', format="xml")
        except RpcError:
            output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()
    else:
        output_dict_xml['core_dumps_xml'] = dev.rpc.get_system_core_dumps()
    if dev.facts['2RE']:
        try:
            output_dict_xml['storage_xml'] = dev.rpc.cli('show system storage invoke-on all-routing-engines',
                                                         format="xml")
        except RpcError:
            output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()
    else:
        output_dict_xml['storage_xml'] = dev.rpc.get_system_storage()
    output_dict_xml['cos_xml'] = dev.rpc.get_cos_interface_map_information(dev_timeout=60)
    output_dict_xml['resource_monitor_xml'] = dev.rpc.get_resource_monitor_summary_fpc_information()

    return output_dict_xml


def unknown_get_output(dev, output_dict_xml):
    hostname = dev.facts['hostname']
    output_dict_xml['inventory_xml'] = dev.rpc.get_chassis_inventory()
    output_dict_xml['re_xml'] = dev.rpc.get_route_engine_information()
    output_dict_xml['fpc_xml'] = dev.rpc.get_fpc_information()
    output_dict_xml['fpc_detail_xml'] = dev.rpc.get_fpc_information(detail=True)
    output_dict_xml['alarm_xml'] = dev.rpc.get_system_alarm_information()
    output_dict_xml['environment_xml'] = dev.rpc.get_environment_information()
    output_dict_xml['interface_xml'] = dev.rpc.get_interface_information(level='media', dev_timeout=60)
    output_dict_xml['uptime'] = dev.rpc.get_system_uptime_information()
    try:
        output_dict_xml['power_xml'] = dev.rpc.get_power_usage_information()
    except RpcError:
        logging.error(f'{hostname} - power command unsupported - RpcError')
        output_dict_xml['power_xml'] = None

    try:
        output_dict_xml['snapshot_xml'] = dev.rpc.get_snapshot_information()
    except RpcError:
        logging.error(f'{hostname} - snapshot command - RpcError')
        output_dict_xml['snapshot_xml'] = None

    try:
        output_dict_xml['storage_xml'] = dev.rpc.cli('show system storage all-members', format="xml")
    except RpcError:
        try:
            if dev.facts['2RE']:
                output_dict_xml['storage_xml'] = dev.rpc.cli('show system storage invoke-on all-routing-engines',
                                                             format="xml")
            else:
                output_dict_xml['storage_xml'] = dev.rpc.cli('show system storage', format="xml")
        except RpcError:
            output_dict_xml['storage_xml'] = dev.rpc.cli('show system storage', format="xml")

    try:
        output_dict_xml['core_dumps_xml'] = dev.rpc.cli('show system core-dumps all-members', format="xml")
    except RpcError:
        try:
            if dev.facts['2RE']:
                output_dict_xml['core_dumps_xml'] = dev.rpc.cli('show system core-dumps routing-engine both',
                                                                format="xml")
            else:
                output_dict_xml['core_dumps_xml'] = dev.rpc.cli('show system core-dumps', format="xml")
        except RpcError:
            logging.error(f'{hostname} - core-dumps command unsupported - RpcError')
            output_dict_xml['core_dumps_xml'] = None

    try:
        if dev.facts['2RE'] and (
                dev.facts['RE0']['model'] == 'RE-S-2X00x6' or dev.facts['RE1']['model'] == 'RE-S-2X00x6'):
            output_dict_xml['vmhost_version_xml'] = dev.rpc.cli('show vmhost version routing-engine both', format="xml")
    except RpcError:
        logging.error(f'{hostname} - device does not support VMHOST - RpcError')
        output_dict_xml['vmhost_version_xml'] = None

    try:
        output_dict_xml['cos_xml'] = dev.rpc.get_cos_interface_map_information(dev_timeout=60)
    except RpcError:
        logging.error(f'{hostname} - cos command - RpcError')
        output_dict_xml['cos_xml'] = None

    try:
        output_dict_xml['network_services_xml'] = dev.rpc.network_services()
    except RpcError:
        logging.error(f'{hostname} - network-services command - RpcError')
        output_dict_xml['network_services_xml'] = None

    try:
        output_dict_xml['resource_monitor_xml'] = dev.rpc.get_resource_monitor_summary_fpc_information()
    except RpcError:
        logging.error(f'{hostname} - resource-monitor command unsupported - RpcError')
        output_dict_xml['resource_monitor_xml'] = None

    try:
        output_dict_xml['optics_xml'] = dev.rpc.get_interface_optics_diagnostics_information()
    except RpcError:
        logging.error(f'{hostname} - diagnostic optics command unsupported- RpcError')
        output_dict_xml['optics_xml'] = None

    return output_dict_xml
