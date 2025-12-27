control 'SV-216239' do
  title 'The limitpriv zone option must be set to the vendor default or less permissive.'
  desc 'Solaris zones can be assigned privileges generally reserved for the global zone using the "limitpriv" zone option. Any privilege assignments in excess of the vendor defaults may provide the ability for a non-global zone to compromise the global zone.'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

List the non-global zones on the system.

# zoneadm list -vi | grep -v global

From the output list of non-global zones found, determine if any are Kernel zones.

# zoneadm list -cv | grep [zonename] | grep solaris-kz

Exclude any Kernel zones found from the list of local zones.

List the configuration for each zone.

# zonecfg -z [zonename] info |grep limitpriv

If the output of this command has a setting for limitpriv and it is not:
limitpriv: default

this is a finding.'
  desc 'fix', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

The Zone Security profile is required:

Change the "limitpriv" setting to default. 

# pfexec zonecfg -z [zone] set limitpriv=default'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17477r373093_chk'
  tag severity: 'low'
  tag gid: 'V-216239'
  tag rid: 'SV-216239r603268_rule'
  tag stig_id: 'SOL-11.1-100020'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17475r373094_fix'
  tag 'documentable'
  tag legacy: ['SV-60767', 'V-47895']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
