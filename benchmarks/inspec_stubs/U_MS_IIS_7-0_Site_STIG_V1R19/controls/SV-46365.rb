control 'SV-46365' do
  title 'The application pool identity must be defined for each web-site.'
  desc 'The Worker Process Identity is the user defined to run an application pool. The IIS 7 worker processes, by default runs under the NetworkService account. Creating a custom identity for each application pool will better track issues occurring within each web-site. When a custom identity is used, the rights and privileges must not exceed those associated with the NetworkService security principal.'
  desc 'check', 'This check is only applicable when IIS is running on Windows Server 2008 SP2 or Windows Server 2008 R2.

1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the Process Model section and ensure the value for Identity is set to ApplicationPoolIdentity, Network Service or a custom identity. If not, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the Process Model section and set the value for Identity to ApplicationPoolIdentity, Network Service or a custom identity with rights and privileges equal to or less than the built-in security principle.'
  impact 0.7
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32866r3_chk'
  tag severity: 'high'
  tag gid: 'V-13713'
  tag rid: 'SV-46365r2_rule'
  tag stig_id: 'WA000-WI6040 IIS7'
  tag gtitle: 'WA000-WI6040'
  tag fix_id: 'F-29010r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
