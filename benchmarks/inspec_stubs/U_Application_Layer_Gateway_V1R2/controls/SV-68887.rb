control 'SV-68887' do
  title 'The ALG must deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).'
  desc "A deny-all, permit-by-exception network communications traffic policy ensures that only those connections which are essential and approved are allowed.

As a managed interface, the ALG must block all inbound and outbound network communications traffic to the application being managed and controlled unless a policy filter is installed to explicitly allow the traffic. The allow policy filters must comply with the site's security policy. A deny all, permit by exception network communications traffic policy ensures that only those connections which are essential and approved, are allowed.

This requirement applies to both inbound and outbound network communications traffic. All inbound and outbound traffic for which the ALG is acting as an intermediary or proxy must be denied by default."
  desc 'check', 'Verify the ALG denies network communications traffic by default and allows network communications traffic by exception on both inbound and outbound interfaces.

If the ALG does not deny network communications traffic by default and allow network communications traffic by exception on both inbound and outbound interfaces, this is a finding.'
  desc 'fix', 'Configure the ALG to deny network communications traffic by default and allow network communications traffic by exception on both inbound and outbound interfaces.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55261r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54641'
  tag rid: 'SV-68887r1_rule'
  tag stig_id: 'SRG-NET-000202-ALG-000124'
  tag gtitle: 'SRG-NET-000202-ALG-000124'
  tag fix_id: 'F-59497r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
