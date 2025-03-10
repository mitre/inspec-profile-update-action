control 'SV-239137' do
  title 'The Photon operating system must prohibit the use of cached authenticators after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'At the command line, execute the following command:

# /opt/likewise/bin/lwregshell list_values "HKEY_THIS_MACHINE\\Services\\lsass\\Parameters\\Providers\\ActiveDirectory"|grep "CacheEntryExpiry"

If the value returned is not 14400 or less, this is a finding.'
  desc 'fix', 'At the command line, execute the following command:

# /opt/likewise/bin/lwregshell set_value "[HKEY_THIS_MACHINE\\Services\\lsass\\Parameters\\Providers\\ActiveDirectory]" CacheEntryExpiry 14400'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42348r675217_chk'
  tag severity: 'medium'
  tag gid: 'V-239137'
  tag rid: 'SV-239137r675219_rule'
  tag stig_id: 'PHTN-67-000066'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-42307r675218_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
