control 'SV-250636' do
  title 'The operating system must monitor and control communications at the external boundary of the information system and at key internal boundaries within the system.'
  desc 'Unrestricted access to services running on an ESXi host can exposes a host to outside attacks and unauthorized access. Reduce the risk by configuring the ESXi firewall to allow access from authorized networks only.'
  desc 'check', %q(From the vSphere client, select the host, then select "Configuration >> Security Profile". In the "Firewall" section select "Properties". 

For each enabled service, (e.g., ssh, vSphere Web Access, http client), select "Firewall", and verify "Only allow connections from the following networks" is selected and a range of authorized IP addresses is listed.

If any enabled service's firewall entry is not configured for "Only allow connections from the following networks" with a range of authorized IP addresses listed, this is a finding.)
  desc 'fix', 'For each host, from the vSphere client, select the host and go to "Configuration >> Security Profile".  In the "Firewall" section select "Properties".  For each enabled service, (e.g., ssh, vSphere Web Access, http client), select "Firewall", select "Only allow connections from the following networks", and provide a range of authorized IP addresses.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54071r798905_chk'
  tag severity: 'medium'
  tag gid: 'V-250636'
  tag rid: 'SV-250636r798907_rule'
  tag stig_id: 'SRG-OS-000144-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54025r798906_fix'
  tag 'documentable'
  tag legacy: ['SV-51255', 'V-39397']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
