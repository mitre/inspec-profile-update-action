control 'SV-33314' do
  title 'The production website must utilize SHA1 encryption for Machine Key.'
  desc 'The Machine Key element of the ASP.NET web.config specifies the algorithm and keys that
ASP.NET will use for encryption.  The Machine Key feature can be managed to specify hashing and encryption settings for application services such as view state, forms authentication, membership and roles, and anonymous identification. Ensuring a strong encryption method can mitigate the risk of data tampering in crucial functional areas such as forms authentication cookies or view state.'
  desc 'check', '1. Open the "IIS Manager".
2. Click the site name under review.
3. Double-click the "Machine Key" in the website "Home Pane".
4. Ensure "SHA1" is selected for the "Validation method".

If not, this is a finding.'
  desc 'fix', '1. Open the "IIS Manager".
2. Click the site name under review.
3. Double-click the "Machine Key" in the website "Home Pane".
4. Set the "Validation method" to "SHA1".'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32882r5_chk'
  tag severity: 'medium'
  tag gid: 'V-26026'
  tag rid: 'SV-33314r4_rule'
  tag stig_id: 'WA000-WI6180 IIS7'
  tag gtitle: 'WA000-WI6180'
  tag fix_id: 'F-29031r4_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
