# Lacework Org-level Vuln Export

This project is meant to provide an example of how to export vulnerability data from Lacework across an entire organization. To perform these actions, the code utilizes the [Lacework Python SDK](https://github.com/lacework/python-sdk) and the [Lacework Reports](https://github.com/lacework-dev/laceworkreports) modules to collect and format the output data.

## Examples

The [org_host_vuln_export.py](src/org_host_vuln_export.py) file in this repository provides an example that iterates across all Lacework Accounts within a Lacework Organization to export all Critical and High severity vulnerabilities, which are 'New', 'Active', or 'Reopened', and have fixes available.

## How To Run

### Lacework Authentication

Since the code uses the Lacework Python SDK, authentication for your Lacework account can be provided using any of the following methods:

- Lacework CLI Profile
  - `LW_PROFILE` Environment Variable
- Lacework API Account/Key/Secret as follows:

| Environment Variable | Description                                                          | Required |
| -------------------- | -------------------------------------------------------------------- | :------: |
| `LW_ACCOUNT`         | Lacework account/organization domain (i.e. `<account>`.lacework.net) |    Y     |
| `LW_SUBACCOUNT`      | Lacework sub-account                                                 |    N     |
| `LW_API_KEY`         | Lacework API Access Key                                              |    Y     |
| `LW_API_SECRET`      | Lacework API Access Secret                                           |    Y     |

### Execution

1. If desired, create a Python virtual environment.
   - `python3 -m venv venv`
   - Activate the virtual environment.
     - `source venv/bin/activate`
2. Install the required modules.
   - `pip install -r requirements.txt --upgrade`
3. Execute the vulnerability export script.
   - `python ./src/org_host_vuln_export.py`
