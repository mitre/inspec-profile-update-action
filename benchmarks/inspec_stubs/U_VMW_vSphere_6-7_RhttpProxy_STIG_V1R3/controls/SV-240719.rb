control 'SV-240719' do
  title 'The rhttpproxy must use cryptography to protect the integrity of remote sessions.'
  desc '<0> [object Object]'
  desc 'check', "At the command prompt, execute the following command:

# xmllint --xpath '/config/vmacore/ssl/protocols' /etc/vmware-rhttpproxy/config.xml

Expected result:

<protocols>tls1.2</protocols>

OR

XPath set is empty

If the output does not match the expected result, this is a finding."
  desc 'fix', 'Navigate to and open /etc/vmware-rhttpproxy/config.xml.

Locate the <config>/<vmacore>/<ssl> block and configure <protocols> as follows:

<protocols>tls1.2</protocols>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 RhttpProxy'
  tag check_id: 'C-43952r816677_chk'
  tag severity: 'medium'
  tag gid: 'V-240719'
  tag rid: 'SV-240719r879520_rule'
  tag stig_id: 'VCRP-67-000004'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-43911r679669_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
