control 'SV-104281' do
  title 'Symantec ProxySG must deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).'
  desc "A deny-all, permit-by-exception network communications traffic policy ensures that only connections that are essential and approved are allowed.

As a managed interface, the ALG must block all inbound and outbound network communications traffic to the application being managed and controlled unless a policy filter is installed to explicitly allow the traffic. The allow policy filters must comply with the site's security policy. 

This requirement applies to both inbound and outbound network communications traffic. All inbound and outbound traffic for which the ALG is acting as an intermediary or proxy must be denied by default."
  desc 'check', 'Verify that the ProxySG is configured to deny all traffic by default.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Policy >> Policy Options.
3. Verify that the "Default Proxy Policy" setting is set to "Deny".

If Symantec ProxySG does not deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception), this is a finding.'
  desc 'fix', 'Configure the ProxySG to deny all traffic by default.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Policy >> Policy Options.
3. Set the "Default Proxy Policy" to "Deny" and click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93513r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94327'
  tag rid: 'SV-104281r1_rule'
  tag stig_id: 'SYMP-AG-000570'
  tag gtitle: 'SRG-NET-000202-ALG-000124'
  tag fix_id: 'F-100443r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
