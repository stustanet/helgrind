#compdef helgrindctl

function _helgrind_services {
    # TODO: get the config file from the running command line
    _values 'Services' `jq -M '.Services | keys' /etc/helgrind.json | head -n -1 | tail -n +2 | sed -e 's_"__g'`
}

_arguments '-cfg[Config file]:helgrind.json:_files' \
           "-action[Action to perform]:Action to Perform:(help config apply list revoke reenable)" \
           '-service[Service to configure]:Service:_helgrind_services' \
           '-device[Users device]:Devicename:' \
           '-alias[Users alias]:Alias:' \
           '-name[Full user name]:Name:' \
           '-email[User email]:Email:' \
           '-csr[Certificate request]:CSR:_files' \
           '-out[Output to file]:File:_files'
