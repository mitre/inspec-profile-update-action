control 'SV-234180' do
  title 'The FortiGate device must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'To ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable.

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration log disk setting | grep -i max-log-file-size

The output should be: 
          set max-log-file-size {INTEGER}

If max-log-file-size for local disk storage is not set to the organization-defined audit record storage, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config log disk setting
     #    set max-log-file-size {INTEGER 1 - 100 MB}
     #    set diskfull overwrite
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37365r860665_chk'
  tag severity: 'medium'
  tag gid: 'V-234180'
  tag rid: 'SV-234180r860666_rule'
  tag stig_id: 'FGFW-ND-000105'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-37330r835183_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
