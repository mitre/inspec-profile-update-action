control 'SV-4510' do
  title 'Forwarders are not disabled on the CSS DNS.'
  desc 'CSS DNS is not vulnerable to attacks associated with recursion because it does not support recursion, but does offer a forwarder feature that sends un-resolvable or unsupported requests to another name server.  This feature poses a risk because the forwarder feature merely redirects potential attacks to another name server.'
  desc 'check', 'In the presence of the reviewer, the CSS DNS administrator should enter the following command while in global configuration mode:

show dns-server forwarder

Confirm the DNS server forwarder primary and DNS server forwarder secondary are “Not Configured.”  If either of these is configured, then this is a finding.'
  desc 'fix', 'The CSS DNS administrator should disable forwarders by entering the following command while in global configuration mode: no dns-server forwarder primary (if a primary) or no dns-server forwarder secondary (if a secondary).'
  impact 0.5
  ref 'DPMS Target Cisco CSS DNS'
  tag check_id: 'C-3423r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4510'
  tag rid: 'SV-4510r1_rule'
  tag stig_id: 'DNS0925'
  tag gtitle: 'Forwarders are not disabled on the CSS DNS.'
  tag fix_id: 'F-4395r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
