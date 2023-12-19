control 'SV-32480' do
  title 'Log files must consist of the required data fields.'
  desc 'Log files are a critical component to the successful management of an IS used within the DoD.  By generating log files with useful information web administrators can leverage them in the event of a disaster, malicious attack, or other site specific needs.'
  desc 'check', 'Follow the procedures below for each site under review:

1. Open the IIS Manager.
2. Click the site name.
3. Click the Logging icon.
4. Under Format select W3C.
5. Click Select Fields, ensure at a minimum the following fields are checked: Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer. If logging is not enabled, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name.
3. Click the Logging icon.
4. Under Format select W3C.
5. Select the following fields: Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32795r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13688'
  tag rid: 'SV-32480r3_rule'
  tag stig_id: 'WG242 IIS7'
  tag gtitle: 'WG242'
  tag fix_id: 'F-29074r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
