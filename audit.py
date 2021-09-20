import pandas as pd
import numpy as np
from jnpr.junos import Device
import re as regex
from itertools import groupby
import os
import logging
from time import strftime, localtime
from multiprocessing import Pool
from lxml import etree
from datetime import timezone, datetime
from jnpr.junos.exception import ProbeError, ConnectAuthError, RpcError, ConnectTimeoutError, ConnectError

from xml_parse import parse_xml, parse_xml_inventory, parse_xml_cos, \
    parse_xml_coredumps, parse_xml_storage, parse_xml_w_duplicates, parse_xml_uptime, \
    ex_get_output, mx104_get_output, mx_small_get_output, \
    mx_classical_get_output, tseries_get_output, \
    qfx10002_get_output, qfx10k_get_output, unknown_get_output

dir_path = os.path.dirname(os.path.realpath(__file__))

if not os.path.exists('logs'):
    os.makedirs('logs', 0o755)
elif not os.path.exists('result'):
    os.makedirs('result', 0o755)
elif not os.path.exists('data'):
    os.makedirs('data', 0o755)
elif not os.path.exists('raw_data'):
    os.makedirs('raw_data', 0o755)

logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
logging.getLogger("ncclient").setLevel(logging.WARNING)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    filename=dir_path + '/logs/' + strftime("%Y-%m-%d", localtime()) + '_summary.log')

raw_path = dir_path + '/raw_data/' + strftime("%Y-%m-%d", localtime()) + '_'
result_path = dir_path + '/result/' + strftime("%Y-%m-%d", localtime()) + '_'
MX = ['MX80', 'MX104', 'MX480', 'MX960', 'MX80', 'MX240', 'MX5']
QFX10k = ['QFX100']
EX_old = ['EX45', 'EX42', 'EX22']
EX_new = ['EX43', 'EX46']
T_series = ['T1600', 'T4000']

try:
    errors = pd.read_csv(dir_path + '/data/errors.csv').drop(columns='Unnamed: 0')
except:
    errors = pd.DataFrame()

error = pd.DataFrame()
valid_credential = pd.DataFrame()

vmhost_columns = ['re',
                  'current_boot_disk',
                  'current_root_set',
                  'upgrade_time',
                  'primary_VMHost_version',
                  'primary_VMHost_root',
                  'primary_VMHost_root_short',
                  'primary_VMHost_core',
                  'primary_VMHost_core_short',
                  'primary_junos_disk',
                  'primary_junos_disk_short',
                  'backup_VMHost_version',
                  'backup_VMHost_root',
                  'backup_VMHost_root_short',
                  'backup_VMHost_core',
                  'backup_VMHost_core_short',
                  'backup_junos_disk',
                  'backup_junos_disk_short']

paramaters = ['inventory', 're', 'fpc', 'fpc_detail', 'resource_monitor', 'uptime', 'alarm', 'pems', 'zone',
              'environment', 'cos',
              'vmhost_version', 'network_services', 'core_dumps', 'snapshot', 'interface', 'storage', 'optics',
              'valid_credential', 'error']


def clean_text(df):
    for n, i in enumerate(df.dtypes):
        if i == 'object':
            df.loc[:, list(df.columns)[n]] = \
                df.loc[:, list(df.columns)[n]].str.replace('\n', '')
    return df


def connect_n_collect(host):
    attempt = 1
    output_dict = {}
    for parameter in paramaters:
        output_dict[parameter] = pd.DataFrame()

    output_dict_xml = {'snapshot_xml': None,
                       'core_dumps_xml': None,
                       'storage_xml': None,
                       'inventory_xml': None,
                       'vmhost_version_xml': None,
                       're_xml': None,
                       'fpc_xml': None,
                       'fpc_detail_xml': None,
                       'uptime': None,
                       'alarm_xml': None,
                       'environment_xml': None,
                       'interface_xml': None,
                       'optics_xml': None,
                       'cos_xml': None,
                       'power_xml': None,
                       'network_services_xml': None,
                       'resource_monitor_xml': None}
    try:
        valid_credential = pd.read_csv(dir_path + '/data/valid_credential.csv').drop(columns='Unnamed: 0')
    except:
        logging.error(f'There is no valid credential')
        valid_credential = None

    if valid_credential is not None and host in list(valid_credential.loc[:, 'ip-address']):
        user = valid_credential.loc[valid_credential['ip-address'] == host, 'username'].iloc[0]
        passwd = valid_credential.loc[valid_credential['ip-address'] == host, 'passwd'].iloc[0]
        hostname = valid_credential.loc[valid_credential['ip-address'] == host, 'hostname'].iloc[0]
        logging.debug(f'{hostname}:{host} - found known credentials')

        valid_credential = pd.DataFrame({'username': user, 'passwd': user}, index=[0])

        with Device(host=host, user=user, passwd=passwd, port=22, ssh_config='/home/dichigis/.ssh/config', timeout=40) \
                as dev:
            model = dev.facts['model']
            hostname = dev.facts['hostname']
            version = dev.facts['version']
            logging.info(f'{hostname}:{host} - Connected by known credentials')

            try:
                if model in ['EX2200-24T-4G', 'EX4200-24F', 'EX4200-48T', 'EX4300-48T', 'EX4650-48Y-8C',
                             'EX4550-32F', 'QFX5100-48T-6Q', 'QFX5100-48S-6Q']:
                    output_dict_xml = ex_get_output(dev=dev, output_dict_xml=output_dict_xml)
                elif model in ['MX5-T', 'MX80', 'MX80-P']:
                    output_dict_xml = mx_small_get_output(dev=dev, output_dict_xml=output_dict_xml)
                elif model in ['MX104']:
                    output_dict_xml = mx104_get_output(dev=dev, output_dict_xml=output_dict_xml)
                elif model in ['MX240', 'MX480', 'MX960']:
                    output_dict_xml = mx_classical_get_output(dev=dev, output_dict_xml=output_dict_xml)
                elif model in ['T1600', 'T4000']:
                    output_dict_xml = tseries_get_output(dev=dev, output_dict_xml=output_dict_xml)
                elif model in ['QFX10002-72Q']:
                    output_dict_xml = qfx10002_get_output(dev=dev, output_dict_xml=output_dict_xml)
                elif model in ['QFX10016']:
                    output_dict_xml = qfx10k_get_output(dev=dev, output_dict_xml=output_dict_xml)
                else:
                    logging.info(f'Unmatch - {model}')
                    output_dict_xml = unknown_get_output(dev=dev, output_dict_xml=output_dict_xml)
            except Exception as err:
                output_dict['error'] = pd.DataFrame({'time': [strftime("%Y-%m-%d %H:%M:%S", localtime())],
                                                     'ip': [host],
                                                     'error': [err]}, index=[0])
                logging.error(f'{host} - {err}')
                return output_dict

            logging.info(f'{hostname}:{host} - Information collected by known credentials')

    else:
        logging.error(f'{host} - let\'s try a few known credential')
        credential = pd.read_csv(dir_path + '/data/credential.csv').drop(columns='Unnamed: 0')
        credential_list = [i for i, _ in credential.groupby(['username', 'passwd'])]
        for i in credential_list:
            try:
                logging.info(f'Trying to connect {host} - {i[0]} - {i[1]}. Attempt {attempt} of {len(credential)}')
                with Device(host=host, user=i[0], passwd=i[1], port=22, ssh_config='/home/dichigis/.ssh/config',
                            timeout=40) \
                        as dev:
                    model = dev.facts['model']
                    hostname = dev.facts['hostname']
                    version = dev.facts['version']
                    logging.info(f'{hostname}:{host} - Connected')
                    valid_credential = pd.DataFrame({'username': i[0], 'passwd': i[1]}, index=[0])

                    try:
                        if model in ['EX2200-24T-4G', 'EX4200-24F', 'EX4200-48T', 'EX4300-48T', 'EX4650-48Y-8C',
                                     'EX4550-32F', 'QFX5100-48T-6Q', 'QFX5100-48S-6Q']:
                            output_dict_xml = ex_get_output(dev=dev, output_dict_xml=output_dict_xml)
                        elif model in ['MX5-T', 'MX80', 'MX80-P']:
                            output_dict_xml = mx_small_get_output(dev=dev, output_dict_xml=output_dict_xml)
                        elif model in ['MX104']:
                            output_dict_xml = mx104_get_output(dev=dev, output_dict_xml=output_dict_xml)
                        elif model in ['MX240', 'MX480', 'MX960']:
                            output_dict_xml = mx_classical_get_output(dev=dev, output_dict_xml=output_dict_xml)
                        elif model in ['T1600', 'T4000']:
                            output_dict_xml = tseries_get_output(dev=dev, output_dict_xml=output_dict_xml)
                        elif model in ['QFX10002-72Q']:
                            output_dict_xml = qfx10002_get_output(dev=dev, output_dict_xml=output_dict_xml)
                        elif model in ['QFX10016']:
                            output_dict_xml = qfx10k_get_output(dev=dev, output_dict_xml=output_dict_xml)
                        else:
                            logging.info(f'Unmatch - {model}')
                            output_dict_xml = unknown_get_output(dev=dev, output_dict_xml=output_dict_xml)
                    except Exception as err:
                        output_dict['error'] = pd.DataFrame({'time': [strftime("%Y-%m-%d %H:%M:%S", localtime())],
                                                             'ip': [host],
                                                             'error': [err]}, index=[0])
                        logging.error(f'{host} - {err}')
                        return output_dict

                    logging.info(f'{hostname}:{host} - Information collected')

            except ProbeError as err:
                output_dict['error'] = pd.DataFrame({'time': [strftime("%Y-%m-%d %H:%M:%S", localtime())],
                                                     'ip': [host],
                                                     'error': ['Unreachable']}, index=[0])
                logging.error(f'{host} - {err}')
                return output_dict
            except ConnectAuthError:
                if attempt == len(credential):
                    output_dict['error'] = pd.DataFrame({'time': [strftime("%Y-%m-%d %H:%M:%S", localtime())],
                                                         'ip': [host],
                                                         'error': ['AuthError']}, index=[0])
                    logging.error(f'{host} - Auth Error {i[0]} - {i[1]}. All credential is failed')
                    return output_dict
                else:
                    logging.error(f'{host} - Auth Error. Try next')
                    attempt += 1
                    continue
            except ConnectTimeoutError as err:
                output_dict['error'] = pd.DataFrame({'time': [strftime("%Y-%m-%d %H:%M:%S", localtime())],
                                                     'ip': [host],
                                                     'error': ['ConnectTimeout']}, index=[0])
                logging.error(f'{host} - {err}')
                return output_dict
            except ConnectError as err:
                output_dict['error'] = pd.DataFrame({'time': [strftime("%Y-%m-%d %H:%M:%S", localtime())],
                                                     'ip': [host],
                                                     'error': ['notJuniper']}, index=[0])
                logging.error(f'{host} - {err}')
                return output_dict
            except Exception as err:
                logging.error(f'Unexpected error - {host} - {err}')

    logging.info(f'{hostname}:{host} - parsing...')

    inventory_df = pd.concat(parse_xml_inventory(root=output_dict_xml['inventory_xml'],
                                                 fpc=None,
                                                 mic=None,
                                                 pic=None,
                                                 df_list=[])).reset_index(drop=True)
    inventory_df['hostname'] = hostname
    inventory_df['ip-address'] = host
    inventory_df['version'] = version
    inventory_df['model'] = model
    output_dict['inventory'] = inventory_df

    logging.debug(f'{hostname}:{host} - INVENTORY - DONE - {len(inventory_df)}')

    re_df = pd.concat(parse_xml(root=output_dict_xml['re_xml'], df_list=[])).reset_index(drop=True)
    logging.debug(f'{hostname}:{host} - ROUTING-ENGINE - DONE - {len(re_df)}')

    fpc_df = pd.concat(parse_xml(root=output_dict_xml['fpc_xml'], df_list=[])).reset_index(drop=True)
    logging.debug(f'{hostname}:{host} - FPC - DONE - {len(fpc_df)}')

    fpc_detail_df = pd.concat(parse_xml(root=output_dict_xml['fpc_detail_xml'], df_list=[])).reset_index(drop=True)
    logging.debug(f'{hostname}:{host} - FPC DETAIL - DONE - {len(fpc_detail_df)}')

    environment_df = pd.concat(parse_xml(root=output_dict_xml['environment_xml'], df_list=[])).reset_index(drop=True)
    logging.debug(f'{hostname}:{host} - ENVIRONMENT - DONE - {len(environment_df)}')

    uptime_df = pd.concat(parse_xml_uptime(root=output_dict_xml['uptime'], parent_type='', df_list=[])).reset_index(
        drop=True)
    logging.debug(f'{hostname}:{host} - UPTIME - DONE - {len(environment_df)}')

    if output_dict_xml['vmhost_version_xml'] is not None:
        vmhost_version_df = pd.DataFrame()
        for element in output_dict_xml['vmhost_version_xml'].findall('.//multi-routing-engine-item'):
            re = element[0].text
            output_text = element[1].text
            value = []
            if regex.search(r'.*Version get failed.*', output_text):
                value.append(re)
                failed_value = ['FAIL'] * (len(vmhost_columns) - 1)
                value.extend(failed_value)
            else:
                value.append(re)
                try:
                    value.append(regex.search(r'Current boot disk:\s(.*)', output_text).group(1))
                    value.append(regex.search(r'Current root set:\s(.*)', output_text).group(1))
                    value.append(regex.search(r'Primary Disk, Upgrade Time:\s(.*)', output_text).group(1))
                    value.append(regex.search(r'.*Version: set p\nVMHost Version:\s(.*)', output_text).group(1))
                    value.append(regex.search(r'.*Version: set p\n.*\nVMHost Root:\s(.*)', output_text).group(1))
                    value.append(
                        regex.search(r'.*Version: set p\n.*\nVMHost Root:\svmhost-x86_64-(.*)-20.*', output_text).group(
                            1))
                    value.append(regex.search(r'.*Version: set p\n.*\n.*\nVMHost Core:\s(.*)', output_text).group(1))
                    value.append(regex.search(r'.*Version: set p\n.*\n.*\nVMHost Core:\svmhost-core-x86_64-(.*)-20.*',
                                              output_text).group(1))
                    value.append(
                        regex.search(r'.*Version: set p\n.*\n.*\n.*\n.*\nJunos Disk:\s(.*)', output_text).group(1))
                    value.append(
                        regex.search(r'.*Version: set p\n.*\n.*\n.*\n.*\nJunos Disk:\sjunos-install-.*-64-(.*)',
                                     output_text).group(1))
                    value.append(regex.search(r'.*Version: set b\nVMHost Version:\s(.*)', output_text).group(1))
                    value.append(regex.search(r'.*Version: set b\n.*\nVMHost Root:\s(.*)', output_text).group(1))
                    value.append(
                        regex.search(r'.*Version: set b\n.*\nVMHost Root:\svmhost-x86_64-(.*)-20.*', output_text).group(
                            1))
                    value.append(regex.search(r'.*Version: set b\n.*\n.*\nVMHost Core:\s(.*)', output_text).group(1))
                    value.append(regex.search(r'.*Version: set b\n.*\n.*\nVMHost Core:\svmhost-core-x86_64-(.*)-20.*',
                                              output_text).group(1))
                    value.append(
                        regex.search(r'.*Version: set b\n.*\n.*\n.*\n.*\nJunos Disk:\s(.*)', output_text).group(1))
                    value.append(
                        regex.search(r'.*Version: set b\n.*\n.*\n.*\n.*\nJunos Disk:\sjunos-install-.*-64-(.*)',
                                     output_text).group(1))
                except Exception as err:
                    logging.error(f'{hostname}:{host} - {err}\n{output_text}')
                    failed_value = ['FAIL'] * (len(vmhost_columns) - 1)
                    value.extend(failed_value)
            vmhost_version_df = pd.concat(
                [vmhost_version_df, pd.DataFrame(columns=vmhost_columns, data=np.array([value]), index=[0])])
            vmhost_version_df['primary_junos_disk_short'] = vmhost_version_df['primary_junos_disk_short'].str.replace(
                '-limited', '', regex=False)
            vmhost_version_df['backup_junos_disk_short'] = vmhost_version_df['backup_junos_disk_short'].str.replace(
                '-limited', '', regex=False)
            logging.debug(f'{hostname}:{host} - VMHOST VERSION - DONE - {len(vmhost_version_df)}')
    else:
        vmhost_version_df = pd.DataFrame()

    if output_dict_xml['alarm_xml'] is not None:
        if output_dict_xml['alarm_xml'].findall('.//no-active-alarms'):
            alarm_df = pd.DataFrame()
        else:
            alarm_df = pd.concat(parse_xml(root=output_dict_xml['alarm_xml'], df_list=[])).reset_index(drop=True)
            logging.debug(f'{hostname}:{host} - ALARMS - DONE - {len(alarm_df)}')
    else:
        alarm_df = pd.DataFrame()

    if output_dict_xml['cos_xml'] is not None:
        cos_df = pd.concat(parse_xml_cos(root=output_dict_xml['cos_xml'], df_list=[])).reset_index(drop=True)
        logging.debug(f'{hostname}:{host} - COS - DONE - {len(cos_df)}')
    else:
        cos_df = pd.DataFrame()

    if output_dict_xml['network_services_xml'] is not None:
        network_services_df = pd.concat(
            parse_xml(root=output_dict_xml['network_services_xml'], df_list=[])).reset_index(drop=True)
        logging.debug(f'{hostname}:{host} - NETWORK-SERVICES - DONE - {len(network_services_df)}')
    else:
        network_services_df = pd.DataFrame()

    if dev.facts['2RE']:
        re_items = output_dict_xml['core_dumps_xml'].findall('.//multi-routing-engine-item')
        core_dumps_list = []
        for item in re_items:
            re = item.xpath('.//re-name')[0].text
            core_dumps_list.extend(parse_xml_coredumps(root=item, re=re, df_list=[]))
    else:
        core_dumps_list = parse_xml_coredumps(root=output_dict_xml['core_dumps_xml'], re='re', df_list=[])

    if len(core_dumps_list) > 0:
        core_dumps_df = pd.concat(core_dumps_list).reset_index(drop=True)
        logging.debug(f'{hostname}:{host} - CORE-DUMPS - DONE - {len(core_dumps_df)}')
    else:
        core_dumps_df = pd.DataFrame()

    try:
        re_storage = output_dict_xml['storage_xml'].findall('.//multi-routing-engine-item')
        storage_list = []
        for item in re_storage:
            if output_dict_xml['storage_xml'].findall('.//error'):
                storage_list.append(pd.DataFrame())
            else:
                re = item.xpath('.//re-name')[0].text
                storage_list.extend(parse_xml_storage(root=item, re=re, df_list=[]))
    except Exception as err:
        logging.error(f'{hostname}:{host} - storage error - {err}')
        storage_list = parse_xml_storage(root=output_dict_xml['storage_xml'], re='re', df_list=[])

    if len(storage_list) > 0:
        storage_df = pd.concat(storage_list).reset_index(drop=True)
        logging.debug(f'{hostname}:{host} - STORAGE - DONE - {len(storage_df)}')
    else:
        storage_df = pd.DataFrame()

    if output_dict_xml['power_xml'] is not None:
        pems = output_dict_xml['power_xml'].findall('.//power-usage-item')
        zone = output_dict_xml['power_xml'].findall('.//power-usage-system')

        zone_df = pd.concat(parse_xml(root=zone, df_list=[])).reset_index(drop=True)
        logging.debug(f'{hostname}:{host} - POWER ZONE - DONE - {len(zone_df)}')

        pems_list = parse_xml(root=pems, df_list=[])
        pems_modified = []
        tmp_df = pd.DataFrame()
        for n, i in enumerate(pems_list):
            if 'name' in i.columns and len(tmp_df) > 0:
                pems_modified.append(tmp_df)
                tmp_df = i
            elif 'name' in i.columns:
                tmp_df = i
            elif n == len(pems_list) - 1:
                tmp_df = pd.concat([tmp_df, i], axis=1)
                pems_modified.append(tmp_df)
            else:
                tmp_df = pd.concat([tmp_df, i], axis=1)

        pems_df = pd.concat(pems_modified)
        logging.debug(f'{hostname}:{host} - PEM - DONE - {len(pems_df)}')
    else:
        pems_df = pd.DataFrame()
        zone_df = pd.DataFrame()

    if output_dict_xml['snapshot_xml'] is not None:
        if output_dict_xml['snapshot_xml'].findall('.//error'):
            snapshot_df = pd.DataFrame()
            if model in ['MX5-T', 'MX80', 'MX80-P']:
                logging.error(f'{hostname}:snapshot:PLEASE CHECK!!!!')
        elif model in ['MX5-T', 'MX80', 'MX80-P', 'T1600', 'T4000'] or dev.facts['version_info'].major[0] < 15:
            snapshot_df = pd.concat(parse_xml(root=output_dict_xml['snapshot_xml'], df_list=[]))
            snapshot_df['package-name'] = snapshot_df['package-name'].str.replace('\n', '')
            snapshot_version = snapshot_df[snapshot_df['package-name'] == 'jdocs']['package-version'].item()
            snapshot_df = snapshot_df[['snapshot-medium', 'creation-date']].dropna()
            snapshot_df['snapshot_version'] = snapshot_version
            logging.debug(f'{hostname}:{host} - SNAPSHOT - DONE - {len(snapshot_df)}')
        else:
            snapshot_data = output_dict_xml['snapshot_xml'].xpath('//output')[0].text
            snapshots_elements = [list(list_element) for split_element, list_element in
                                  groupby(snapshot_data.split('\n'), lambda x: x == "Recovery Snapshots:")
                                  if not split_element]
            non_recovery_output = snapshots_elements[0]
            recovery_output = snapshots_elements[1]

            columns = ['snapshot', 'location', 'date', 'junos_version']
            non_recovery_snapshots_list = []
            value = []

            for i in non_recovery_output:
                if len(i) > 0:
                    if 'No non-recovery snapshots available on the Junos volume' in i:
                        value = [None, 'No', None, 'missing']
                        non_recovery_snapshots_list.append(
                            pd.DataFrame(columns=columns, data=np.array([value])))
                    elif 'Snapshot snap.' in i:
                        value.append(regex.search(r'Snapshot\s(.*):', i).group(1))
                    elif 'Location:' in i:
                        value.append(regex.search(r'Location:\s(.*)', i).group(1))
                    elif 'Creation date:' in i:
                        value.append(regex.search(r'Creation\sdate:\s(.*)', i).group(1))
                    elif 'Junos version:' in i:
                        value.append(regex.search(r'Junos version:\s(.*)', i).group(1))
                        tmp_df = pd.DataFrame(columns=columns, data=np.array([value]))
                        non_recovery_snapshots_list.append(tmp_df)
                        value = []

            non_recovery_snapshot = pd.concat(non_recovery_snapshots_list)
            non_recovery_snapshot['type'] = 'non_recovery'

            for j in recovery_output:
                if 'Date created: ' in j:
                    date = regex.search(r'Date created: (.*)', j).group(1)
                elif 'Junos version:' in j:
                    version = regex.search(r'Junos version: (.*)', j).group(1)
                elif 'Total recovery snapshots: 1' in j:
                    recovery_snapshot = pd.DataFrame(
                        {'date': date, 'junos_version': version, 'location': 'OAM volume',
                         'type': 'recovery',
                         'snapshot': 'recovery.ufs'}, index=[0])
                elif 'mount: /dev/oam: No such file or directory' in j:
                    recovery_snapshot = pd.DataFrame(
                        {'date': None, 'junos_version': None, 'location': 'mount: /dev/oam: No such file or directory',
                         'type': 'recovery',
                         'snapshot': None}, index=[0])
                elif 'No recovery snapshots available on the OAM volume' in j:
                    recovery_snapshot = pd.DataFrame(
                        {'date': None, 'junos_version': 'missing', 'location': 'OAM volume',
                         'type': 'recovery',
                         'snapshot': 'missing'}, index=[0])

            snapshot_df = pd.concat([recovery_snapshot, non_recovery_snapshot])
            logging.debug(f'{hostname}:{host} - SNAPSHOT - DONE - {len(snapshot_df)}')
    else:
        snapshot_df = pd.DataFrame()

    try:
        interface_list = parse_xml(root=output_dict_xml['interface_xml'], df_list=[])
        interface_modified = []
        tmp_df = pd.DataFrame()
        for n, i in enumerate(interface_list):
            if 'name' in i.columns and len(tmp_df) > 0:
                interface_modified.append(tmp_df)
                tmp_df = i
            elif 'name' in i.columns:
                tmp_df = i
            elif n == len(interface_list) - 1:
                tmp_df = pd.concat([tmp_df, i], axis=1)
                interface_modified.append(tmp_df)
            else:
                tmp_df = pd.concat([tmp_df, i], axis=1)

            if len(tmp_df.columns) > len(set(tmp_df.columns)):
                counter = 0
                new_columns = []
                for n, i in enumerate(tmp_df.columns):
                    if list(tmp_df.columns).count(tmp_df.columns[n]) > 1:
                        new_columns.append(i + '_' + str(counter))
                        counter += 1
                    else:
                        new_columns.append(i)
                tmp_df.columns = new_columns
        interface_df = pd.concat(interface_modified)
        logging.debug(f'{hostname}:{host} - INTERFACE - DONE - {len(interface_df)}')

    except Exception as err:
        logging.error(f'{hostname}:{host} - interface - {err}')
        interface_df = pd.DataFrame()

    try:
        optics = parse_xml(root=output_dict_xml['optics_xml'], df_list=[])
        optics_modified = []
        tmp_df = pd.DataFrame()
        for n, i in enumerate(optics):
            if 'name' in i.columns and len(tmp_df) > 0:
                interface = i
                optics_modified.append(tmp_df)
            elif 'name' in i.columns:
                interface = i
            elif 'lane-index' in i.columns:
                tmp_df = pd.concat([interface, i], axis=1)
                optics_modified.append(tmp_df)
            elif n == len(optics) - 1:
                tmp_df = pd.concat([interface, i], axis=1)
                optics_modified.append(tmp_df)
            else:
                tmp_df = pd.concat([interface, i], axis=1)

        optics_df = pd.concat(optics_modified)
        logging.debug(f'{hostname}:{host} - OPTICS - DONE - {len(optics_df)}')
    except Exception as err:
        logging.error(f'{hostname}:{host} - OPTICS - {err}')
        optics_df = pd.DataFrame()

    if output_dict_xml['resource_monitor_xml'] is not None:
        resource_monitor_list = parse_xml_w_duplicates(root=output_dict_xml['resource_monitor_xml'], df_list=[])
        resource_monitor_modified = []

        for n, i in enumerate(resource_monitor_list):
            if 'fpc-slot' in i.columns:
                fpc = i
            elif 'pfe-num' in i.columns:
                resource_monitor_modified.append(pd.concat([fpc, i], axis=1))
            else:
                resource_monitor_modified.append(i)

        resource_monitor_df = pd.concat(resource_monitor_modified)
        logging.debug(f'{hostname}:{host} - RESOURCE-MONITOR - DONE - {len(resource_monitor_df)}')
    else:
        resource_monitor_df = pd.DataFrame()

    output_dict = {'inventory': inventory_df,
                   're': re_df,
                   'fpc': fpc_df,
                   'fpc_detail': fpc_detail_df,
                   'resource_monitor': resource_monitor_df,
                   'alarm': alarm_df,
                   'pems': pems_df,
                   'zone': zone_df,
                   'environment': environment_df,
                   'cos': cos_df,
                   'uptime': uptime_df,
                   'vmhost_version': vmhost_version_df,
                   'network_services': network_services_df,
                   'core_dumps': core_dumps_df,
                   'snapshot': snapshot_df,
                   'interface': interface_df,
                   'storage': storage_df,
                   'optics': optics_df,
                   'valid_credential': valid_credential,
                   'error': pd.DataFrame()}

    for df_name in output_dict.keys():
        df = output_dict[df_name]
        if not df.empty:
            for columns in output_dict[df_name].columns:
                try:
                    output_dict[df_name][columns] = output_dict[df_name][columns].fillna(0)
                    output_dict[df_name][columns] = output_dict[df_name][columns].astype('int')
                except ValueError:
                    try:
                        output_dict[df_name][columns] = output_dict[df_name][columns].astype('float')
                    except ValueError:
                        continue
            output_dict[df_name]['hostname'] = hostname
            output_dict[df_name]['ip-address'] = host

    return output_dict


logging.info(f'Script starts\n===================================')
device_list = pd.read_csv(dir_path + '/data/hosts.csv', sep=';')

with Pool(16) as p:
    audit_list = list(p.map(connect_n_collect, list(device_list['hosts'].unique())))

for df in paramaters:
    locals()[df] = pd.concat([i[df] for i in audit_list if isinstance(i, dict)])

raw_path = dir_path + '/raw_data/' + strftime("%Y-%m-%d", localtime()) + '_'
result_path = dir_path + '/result/' + strftime("%Y-%m-%d", localtime()) + '_'

for df_name in paramaters:
    df = locals()[df_name]
    if not df.empty:
        if df_name == 'error':
            df = pd.concat([error, errors])
            df.reset_index(drop=True).to_csv(dir_path + '/data/errors.csv')
        else:
            df['hostname'] = df['hostname'].str.replace('-re.', '', regex=True)
            df.reset_index(drop=True).to_excel(raw_path + df_name + '.xlsx', engine='xlsxwriter')

optics = clean_text(optics)
interface = clean_text(interface)

description = interface[['name', 'hostname', 'description', 'admin-status', 'oper-status']]
optics = optics[optics.columns[~optics.columns.str.contains("alarm")]]
optics = optics[optics.columns[~optics.columns.str.contains("warn")]]
optics = pd.merge(optics, description, on=["name", "hostname"])
optics['laser-rx-optical-power-dbm'] = optics['laser-rx-optical-power-dbm'].replace('- Inf', '-40').astype('float')
low_rx_optical_power_dbm = optics[(optics['laser-rx-optical-power-dbm'] < -13) & (optics['admin-status'] == 'up')][
    ['hostname', 'name', 'admin-status', 'oper-status', 'laser-rx-optical-power-dbm', 'description']]
optics['module-temperature_celsius'] = optics['module-temperature_celsius'].fillna(0).astype('float')
high_rx_module_temperature_celsius = \
    optics[(optics['module-temperature_celsius'] > 60) & (optics['admin-status'] == 'up')][
        ['hostname', 'name', 'admin-status', 'oper-status', 'module-temperature_celsius', 'description']]

storage = clean_text(storage)
inventory = clean_text(inventory)
fpc_model = inventory[['hostname', 'name', 'description', 'model']].fillna('Unknown')
fpc_model = fpc_model[fpc_model.name.str.contains('FPC')]
fpc_model['name'] = fpc_model['name'].str.replace('FPC', 'fpc')
fpc_model['name'] = fpc_model['name'].str.replace(' ', '')
fpc_model = fpc_model[~fpc_model['name'].str.contains('CPU')]
fpc_model = fpc_model[~fpc_model['name'].str.contains('MIC')]
fpc_model = fpc_model[~fpc_model['name'].str.contains('PIC')]
re_model = inventory[['hostname', 'name', 'description', 'model']].fillna('Unknown')
re_model = re_model[re_model['name'].str.contains('Routing')]
re_model['name'] = re_model['name'].str.replace('Routing Engine', 're')
re_model['name'] = re_model['name'].str.replace(' ', '')
model = pd.concat([re_model, fpc_model])
for i in ['total-blocks', 'used-blocks', 'available-blocks']:
    storage[i] = storage[i] * 512 / 1.074e+9
storage = storage.rename(columns={'total-blocks': 'total_gibibytes',
                                  'used-blocks': 'used_gibibytes',
                                  'available-blocks': 'available_gibibytes',
                                  're-name': 'name'})
storage = pd.merge(storage, model, on=["name", "hostname"])
low_space = storage[(storage['used-percent'] > 80) & (storage['available_gibibytes'] > 0)]
low_space = low_space[['hostname', 'ip-address', 'description', 'name', 'mounted-on', 'filesystem-name',
                       'used-percent', 'total_gibibytes', 'total-blocks_format', 'used_gibibytes',
                       'used-blocks_format', 'available_gibibytes', 'available-blocks_format']]

re = clean_text(re)
re_cpu_temperature = re[re['cpu-temperature_celsius'] > 60][['hostname', 'model', 'cpu-temperature']]
re_reboot = re[re['up-time_seconds'] / 86400 < 14][
    ['hostname', 'ip-address', 'slot', 'mastership-state', 'status', 'up-time', 'start-time', 'last-reboot-reason']]
re_memory_buffer_utilization = re[re['memory-buffer-utilization'] > 50][
    ['hostname', 'model', 'memory-dram-size', 'memory-buffer-utilization']]
re_fail_state = re[re['status'] != 'OK']

try:
    high_load_cpu_re = \
        re[((re['cpu-idle3'] < 50) | (re['cpu-idle2'] < 50) | (re['cpu-system2'] > 30) | (re['cpu-system3'] > 30)) & (
                    re['mastership-state'] == 'master')][
            ['hostname', 'model', 'slot', 'cpu-idle2', 'cpu-idle3', 'cpu-system2', 'cpu-system3']]
except Exception as err:
    logging.error(f'high_load_cpu_re - {err}')

alarm = clean_text(alarm)
alarm.drop(columns=['active-alarm-count'], inplace=True)
main_alarm = alarm[~((alarm['alarm-description'].fillna('Unnkown').str.contains('Link down')) | (
    alarm['alarm-description'].fillna('Unnkown').str.contains('Backup RE Active')))].dropna()
main_alarm['alarm-time'] = pd.to_datetime(main_alarm['alarm-time_seconds'], unit='s') + pd.Timedelta(3, unit="h")
main_alarm.drop(columns=['alarm-type', 'alarm-time_seconds'], inplace=True)
main_alarm['alarm-time-ago'] = pd.Timestamp.now() - main_alarm['alarm-time']
main_alarm = main_alarm[['hostname', 'alarm-time', 'alarm-time-ago', 'alarm-description']]
last_week_alarm = main_alarm[main_alarm['alarm-time-ago'] < pd.Timedelta(7, unit='day')]
environment = clean_text(environment)
environment_status = environment[environment['status'] != 'OK'][['hostname', 'name', 'status']]
environment_hot = environment[environment['temperature_celsius'] > 60][
    ['hostname', 'name', 'temperature_celsius']].sort_values(by='temperature_celsius', ascending=False)
fans = environment[
    environment['comment'].str.contains('intermediate-speed') | environment['comment'].str.contains('high speed')][
    ['hostname', 'comment']]
environment_hot = pd.merge(environment_hot, fans, on='hostname')
core_dumps = clean_text(core_dumps)
core_count_series = core_dumps.groupby(['hostname', 're-name'])['file-name'].count()
core_size_series = core_dumps.groupby(['hostname', 're-name'])['file-size'].sum() / 1048576
core_time_series = pd.to_datetime(core_dumps.groupby(['hostname', 're-name'])['file-date'].max(), unit='s')
cores = pd.concat([core_count_series, core_size_series, core_time_series], axis=1).rename(
    columns={'file-name': 'files', 'file-size': 'MB', 'file-date': 'last_date'})
cores['time-ago'] = pd.Timestamp.now() - cores['last_date']
last_cores = []
for _, j in core_dumps.groupby(['hostname', 're-name']):
    j = pd.DataFrame(j.tail(1))
    last_cores.append(j)
last_cores = pd.concat(last_cores)
last_cores = last_cores[['hostname', 're-name', 'file-name']]
cores = pd.merge(cores, last_cores, on=['hostname', 're-name'])
cores = cores.rename(columns={'files': 'total_files', 'file-name': 'last_core_dump'})
cores = cores.sort_values(by='time-ago')
uptime = clean_text(uptime)
ntp_check = uptime.loc[:, ['hostname', 'time-source']]
ntp_check.dropna(inplace=True)
ntp_check = ntp_check[~ntp_check['time-source'].str.contains('NTP CLOCK')]
system_booted = uptime[uptime['type'] == 'system-booted-time'].loc[:, ['hostname', 'date-time_seconds']]
system_booted['date-time_seconds'] = pd.to_datetime(system_booted['date-time_seconds'], unit='s')
system_booted['time-ago'] = pd.Timestamp.now() - system_booted['date-time_seconds']
system_booted = system_booted.rename(
    columns={'date-time_seconds': 'system_booted_date_time', 'time-ago': 'system_booted_time-ago'})
fpc = clean_text(fpc)
fpc = fpc.loc[:, ['hostname', 'slot', 'cpu-15min-avg', 'memory-heap-utilization', 'memory-buffer-utilization']]
fpc_detail = clean_text(fpc_detail)
fpc = pd.merge(fpc_detail, fpc, on=['hostname', 'slot'])
fpc = pd.merge(fpc, system_booted, on='hostname')
fpc['up-time_seconds'] = pd.pandas.to_timedelta(fpc['up-time_seconds'], unit='s')
fpc['time_reboot'] = fpc['system_booted_time-ago'] - fpc['up-time_seconds']
fpc['start-time_seconds'] = pd.to_datetime(fpc['start-time_seconds'], unit='s')
fpc_rebooted = fpc[(fpc['time_reboot'] > pd.Timedelta(2, unit='d')) & (fpc['state'] == 'Online')]
fpc_rebooted = fpc_rebooted.loc[:,
               ['hostname', 'slot', 'start-time_seconds', 'system_booted_date_time', 'up-time_seconds',
                'system_booted_time-ago', 'time_reboot']]
fpc_rebooted = fpc_rebooted.rename(
    columns={'start-time_seconds': 'fpc_booted-date_time', 'up-time_seconds': 'fpc_uptime',
             'system_booted_time-ago': 'system_uptime', 'time_reboot': 'time_diff'})
fpc_rebooted = fpc_rebooted.sort_values(by='time_diff')
fpc_model_slot = fpc_model.rename(columns={'name': 'slot'})
fpc_model_slot['slot'] = fpc_model_slot['slot'].str.replace('fpc', '')
fpc_model_slot['slot'] = fpc_model_slot['slot'].astype('int')
fpc = pd.merge(fpc, fpc_model_slot, on=['hostname', 'slot'])
fpc_utilization = fpc.loc[
    fpc['state'] == 'Online', ['hostname', 'slot', 'description', 'cpu-15min-avg', 'memory-heap-utilization',
                               'memory-buffer-utilization', 'memory-dram-size']]
cos = clean_text(cos)
scheduler_map = cos.loc[:, ['hostname', 'interface-name', 'scheduler-map-name', 'interface-queues-supported',
                            'interface-queues-in-use']]
description = description.rename(columns={'name': 'interface-name'})
scheduler_map = pd.merge(scheduler_map, description, on=['hostname', 'interface-name'])
scheduler_map = scheduler_map.loc[(scheduler_map['admin-status'] == 'up') & (
            scheduler_map['interface-name'].str.contains('xe') | scheduler_map['interface-name'].str.contains('ge') |
            scheduler_map['interface-name'].str.contains('ae') | scheduler_map['interface-name'].str.contains('et')), [
                                      'hostname', 'interface-name', 'admin-status', 'oper-status', 'scheduler-map-name',
                                      'description', 'interface-queues-supported', 'interface-queues-in-use']]
scheduler_map_default = scheduler_map[scheduler_map['scheduler-map-name'] == '<default>']
network_services = clean_text(network_services)
inventory_clear = inventory[~(inventory['chassis_style'] == 'inventory')]
inventory_clear = inventory_clear.drop(columns=['chassis_style'])

inventory_clear.loc[inventory_clear['model'].str.contains('|'.join(MX)), 'series'] = 'MX'
inventory_clear.loc[inventory_clear['model'].str.contains('|'.join(QFX10k)), 'series'] = 'QFX10k'
inventory_clear.loc[inventory_clear['model'].str.contains('|'.join(EX_old)), 'series'] = 'EX42_series'
inventory_clear.loc[inventory_clear['model'].str.contains('|'.join(EX_new)), 'series'] = 'EX43_EX46'
inventory_clear.loc[inventory_clear['model'].str.contains('|'.join(T_series)), 'series'] = 'T'
mx_inventory = inventory_clear[inventory_clear['model'].str.contains('MX')]
dpc_check = []
for hostname, j in mx_inventory.groupby('hostname'):
    if any(j.description.str.contains('DPC')):
        dpc_check.append(pd.DataFrame({'hostname': [hostname], 'dpc': [True]}))
    else:
        dpc_check.append(pd.DataFrame({'hostname': [hostname], 'dpc': [False]}))
dpc_check = pd.concat(dpc_check)
network_services = pd.merge(network_services, dpc_check, on='hostname')
network_services = network_services.drop(columns=['ip-address'])
network_services = network_services.loc[:, ['hostname', 'dpc', 'name']]
network_services = network_services[(network_services['dpc'] == False) & (network_services['name'] != 'Enhanced-IP')]
resource_monitor = clean_text(resource_monitor)
resource_monitor = resource_monitor.loc[:,
                   resource_monitor.columns[~resource_monitor.columns.str.contains('cos-queue-utilization')]]
resource_monitor = resource_monitor.loc[:,
                   resource_monitor.columns[~resource_monitor.columns.str.contains('pfe-information-summary')]]
heap_memory = resource_monitor.loc[resource_monitor['heap-memory-threshold'] > 0, ['hostname', 'heap-memory-threshold']]
resource_monitor_utilization = resource_monitor.loc[:, ['hostname', 'fpc-slot', 'pfe-num', 'used-heap-mem-percent',
                                                        'used-filter-counter-percent', 'used-ifl-counter-percent',
                                                        'used-expansion-memory-percent']]
resource_monitor_utilization = resource_monitor_utilization.dropna()
for column in ['fpc-slot', 'pfe-num', 'used-heap-mem-percent', 'used-filter-counter-percent',
               'used-ifl-counter-percent', 'used-expansion-memory-percent']:
    resource_monitor_utilization[column] = resource_monitor_utilization[column].astype('int')
fpc_model_resource_utilization = fpc_model.copy()
fpc_model_resource_utilization = fpc_model_resource_utilization.rename(columns={'name': 'fpc-slot'})
fpc_model_resource_utilization['fpc-slot'] = fpc_model_resource_utilization['fpc-slot'].str.replace('fpc', '')
fpc_model_resource_utilization['fpc-slot'] = fpc_model_resource_utilization['fpc-slot'].astype('int')
resource_monitor_utilization = pd.merge(resource_monitor_utilization, fpc_model_resource_utilization,
                                        on=['hostname', 'fpc-slot'])

snapshot = clean_text(snapshot)
host_vmhost_re = inventory[inventory['description'] == 'RE-S-2X00x6']['hostname'].unique()
snapshot = snapshot.loc[~snapshot.hostname.isin(host_vmhost_re), :]
host_junos = inventory.loc[:, ['hostname', 'version']].drop_duplicates().reset_index(drop=True)
snapshot = pd.merge(snapshot, host_junos, on='hostname')

old_snapshot = snapshot.loc[
    snapshot['snapshot_version'].notnull(), ['hostname', 'snapshot-medium', 'creation-date', 'snapshot_version',
                                             'version']]
old_snapshot['creation-date'] = pd.to_datetime(old_snapshot['creation-date'])
old_snapshot['time-ago'] = pd.Timestamp.now() - old_snapshot['creation-date']
old_snapshot['check'] = True
old_snapshot['check'] = old_snapshot['check'].where(old_snapshot['snapshot_version'] == old_snapshot['version'], False)

new_snapshot = snapshot.loc[
    snapshot['type'].notnull(), ['hostname', 'type', 'date', 'junos_version', 'version', 'location']]
new_snapshot = new_snapshot.rename(columns={'junos_version': 'snapshot_junos_version', 'version': 'junos_version'})
new_snapshot['date'] = pd.to_datetime(new_snapshot['date'], utc=True).dt.tz_convert('Europe/Moscow')
new_snapshot['time_ago'] = (pd.Timestamp.now(tz='Europe/Moscow') - new_snapshot['date']).dt.days
new_snapshot['time_ago'] = new_snapshot['time_ago'].fillna(0)
new_snapshot['time_ago'] = new_snapshot['time_ago'].astype('int')
new_snapshot['date'] = new_snapshot['date'].dt.strftime('%d-%m-%Y')
new_snapshot['check'] = True
new_snapshot['check'] = new_snapshot['check'].where(
    new_snapshot['snapshot_junos_version'] == new_snapshot['junos_version'], False)

vmhost_version = clean_text(vmhost_version)
vmhost_version.loc[vmhost_version['upgrade_time'] == 'FAIL', 'upgrade_time'] = vmhost_version.loc[
    vmhost_version['upgrade_time'] == np.NAN, 'upgrade_time']
vmhost_version['upgrade_time'] = pd.to_datetime(vmhost_version['upgrade_time'], utc=False)
vmhost_version['upgrade_time_ago'] = datetime.now(tz=timezone.utc) - vmhost_version['upgrade_time']
vmhost_version['upgrade_time'] = pd.to_datetime(vmhost_version['upgrade_time'], utc=True)
vmhost_version = vmhost_version.loc[:, ['hostname', 're', 'current_boot_disk', 'current_root_set',
                                        'upgrade_time', 'upgrade_time_ago',
                                        'primary_VMHost_root_short', 'backup_VMHost_root_short',
                                        'primary_VMHost_core_short', 'backup_VMHost_core_short',
                                        'primary_junos_disk_short', 'backup_junos_disk_short']]
vmhost_version['upgrade_time'] = vmhost_version['upgrade_time'].dt.strftime('%d-%m-%Y')
vmhost_version['upgrade_time_ago'] = vmhost_version['upgrade_time_ago'].dt.days
vmhost_version['upgrade_time_ago'] = vmhost_version['upgrade_time_ago'].fillna(0)
vmhost_version['upgrade_time_ago'] = vmhost_version['upgrade_time_ago'].astype('int')

zone = clean_text(zone)
sys_capacity = zone.loc[zone['capacity-sys-remaining'] > 0, ['hostname', 'capacity-sys-actual', 'capacity-sys-max',
                                                             'capacity-sys-remaining']]
sys_capacity = sys_capacity.sort_values(by='capacity-sys-remaining')
zone_capacity = zone.loc[
    zone['capacity-sys-remaining'] == 0, ['hostname', 'zone', 'capacity-actual', 'capacity-max', 'capacity-allocated',
                                          'capacity-remaining', 'capacity-actual-usage']]
zone_capacity = zone_capacity.sort_values(by='capacity-remaining')

pems = clean_text(pems)
pems_state = pems.loc[pems['state'] != 'Online', ['hostname', 'name', 'state', 'status']]
pems = pems.loc[
    pems['state'] == 'Online', ['hostname', 'name', 'state', 'zone', 'dc-input', 'capacity-actual', 'capacity-max',
                                'dc-expect-feed', 'dc-actual-feed']]
pems['check'] = True
pems['check'] = pems['check'].where(pems['capacity-actual'] == pems['capacity-max'], False)
inventory_pem = inventory.copy()
inventory_pem['name'] = inventory_pem['name'].fillna('Unknown')
inventory_pem = inventory_pem.loc[inventory_pem['name'].str.contains('PEM'), ['hostname', 'name', 'model-number']]
inventory_power_supply = inventory.copy()
inventory_power_supply['name'] = inventory_power_supply['name'].fillna('Unknown')
inventory_power_supply = inventory_pem.loc[
    inventory_pem['name'].str.contains('Power Supply'), ['hostname', 'name', 'model-number']]
inventory_power_supply['name'] = inventory_power_supply['name'].str.replace('Power Supply', 'PEM')
inventory_pem = pd.concat([inventory_pem, inventory_power_supply])
pems = pd.merge(pems, inventory_pem, on=['hostname', 'name'])

low_rx_optical_power_dbm.reset_index(drop=True).to_excel(result_path + 'low_rx_optical_power_dbm.xlsx',
                                                         engine='xlsxwriter')
high_rx_module_temperature_celsius.reset_index(drop=True).to_excel(
    result_path + 'high_rx_module_temperature_celsius.xlsx', engine='xlsxwriter')
low_space.reset_index(drop=True).to_excel(result_path + 'low_space.xlsx', engine='xlsxwriter')
re_reboot.reset_index(drop=True).to_excel(result_path + 're_reboot.xlsx', engine='xlsxwriter')
re_memory_buffer_utilization.reset_index(drop=True).to_excel(result_path + 're_memory_buffer_utilization.xlsx',
                                                             engine='xlsxwriter')
if len(re_fail_state) > 0:
    re_fail_state.reset_index(drop=True).to_excel(result_path + 're_fail_state.xlsx', engine='xlsxwriter')
if len(high_load_cpu_re) > 0:
    high_load_cpu_re.reset_index(drop=True).to_excel(result_path + 'high_load_cpu_re.xlsx', engine='xlsxwriter')

main_alarm.reset_index(drop=True).to_excel(result_path + 'main_alarm.xlsx', engine='xlsxwriter')
last_week_alarm.reset_index(drop=True).to_excel(result_path + 'last_week_alarm.xlsx', engine='xlsxwriter')
environment_status.reset_index(drop=True).to_excel(result_path + 'environment_status.xlsx', engine='xlsxwriter')
environment_hot.reset_index(drop=True).to_excel(result_path + 'environment_hot.xlsx', engine='xlsxwriter')
cores.reset_index(drop=True).to_excel(result_path + 'core_dumps.xlsx', engine='xlsxwriter')
ntp_check.reset_index(drop=True).to_excel(result_path + 'ntp.xlsx', engine='xlsxwriter')
fpc_rebooted.reset_index(drop=True).to_excel(result_path + 'fpc_reboot.xlsx', engine='xlsxwriter')
fpc_utilization.reset_index(drop=True).to_excel(result_path + 'fpc_utilization.xlsx', engine='xlsxwriter')
scheduler_map_default.reset_index(drop=True).to_excel(result_path + 'scheduler_map_default.xlsx', engine='xlsxwriter')
network_services.reset_index(drop=True).to_excel(result_path + 'network_services.xlsx', engine='xlsxwriter')
resource_monitor_utilization.reset_index(drop=True).to_excel(result_path + 'resource_monitor_utilization.xlsx',
                                                             engine='xlsxwriter')
old_snapshot.reset_index(drop=True).to_excel(result_path + 'old_snapshot.xlsx', engine='xlsxwriter')
new_snapshot.reset_index(drop=True).to_excel(result_path + 'new_snapshot.xlsx', engine='xlsxwriter')
vmhost_version.reset_index(drop=True).to_excel(result_path + 'vmhost_version.xlsx', engine='xlsxwriter')
sys_capacity.reset_index(drop=True).to_excel(result_path + 'pems_sys_capacity.xlsx', engine='xlsxwriter')
zone_capacity.reset_index(drop=True).to_excel(result_path + 'pems_zone_capacity.xlsx', engine='xlsxwriter')
pems_state.reset_index(drop=True).to_excel(result_path + 'pems_state.xlsx', engine='xlsxwriter')
pems.reset_index(drop=True).to_excel(result_path + 'pems.xlsx', engine='xlsxwriter')
inventory_clear.reset_index(drop=True).to_excel(result_path + 'inventory.xlsx', engine='xlsxwriter')

logging.info(f'Script stops\n==================================+')
