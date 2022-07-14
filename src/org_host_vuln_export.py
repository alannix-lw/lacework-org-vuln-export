#!/usr/bin/env python

from datetime import datetime, timedelta, timezone

from laceworksdk import LaceworkClient
from laceworkreports import common
from laceworkreports.sdk.DataHandlers import (
    DataHandlerTypes,
    ExportHandler,
    QueryHandler,
)


def get_start_end_times(hours_delta=24):
    """
    Generate start and end times for the vulnerability search
    """
    current_time = datetime.now(timezone.utc)
    start_time = current_time - timedelta(hours=hours_delta)
    start_time = start_time
    end_time = current_time

    return start_time, end_time


if __name__ == '__main__':

    # Instantiate a LaceworkClient
    lw = LaceworkClient()

    # Make Org-level API calls
    lw.set_org_level_access(True)

    # Fetch the Lacework accounts that the user can access
    user_profile_data = lw.user_profile.get().get('data', {})[0]
    lw.set_org_level_access(False)

    # If an org account
    if user_profile_data.get('orgAccount', False):

        # Iterate through all subaccounts
        for subaccount in user_profile_data.get('accounts', []):

            print(f'Sub-Account: {subaccount["accountName"]}')

            # Set the Lacework subaccount
            lw.set_subaccount(subaccount['accountName'])

            # Build start/end times
            start_time, end_time = get_start_end_times(hours_delta=48)

            eh = ExportHandler(
                format=DataHandlerTypes.CSV,
                results=QueryHandler(
                    client=lw,
                    type=common.ObjectTypes.Vulnerabilities.value,
                    object=common.VulnerabilitiesTypes.Hosts.value,
                    start_time=start_time,
                    end_time=end_time,
                    filters=[
                        {
                            'field': 'severity',
                            'expression': 'in',
                            'values': [
                                'Critical',
                                'High'
                            ]
                        },
                        {
                            'field': 'status',
                            'expression': 'in',
                            'values': [
                                'New',
                                'Active',
                                'Reopened'
                            ]
                        },
                        {
                            'field': 'fixInfo.fix_available',
                            'expression': 'eq',
                            'value': 1
                        }
                    ],
                    returns=[
                        'startTime',
                        'mid',
                        'status',
                        'vulnId',
                        'severity',
                        'featureKey',
                        'machineTags',
                        'cveProps',
                        'fixInfo'
                    ],
                ).execute(),
                field_map={
                    'startTime': 'startTime',
                    'instanceId': 'machineTags.InstanceId',
                    'AmiId': 'machineTags.AmiId',
                    'status': 'status',
                    'vulnId': 'vulnId',
                    'vulnDescription': 'cveProps.description',
                    'vulnLink': 'cveProps.link',
                    'severity': 'severity',
                    'package_name': 'featureKey.name',
                    'package_namespace': 'featureKey.namespace',
                    'package_active': 'featureKey.package_active',
                    'version_installed': 'featureKey.version_installed',
                    'fix_available': 'fixInfo.fix_available',
                    'fix_version': 'fixInfo.fixed_version'
                },
                file_path=f'{subaccount["accountName"].lower()}-export.csv',
            ).export()
