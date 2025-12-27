control 'SV-82539' do
  title 'The A10 Networks ADC must not have any shared accounts (other than the emergency administration account).'
  desc 'To assure accountability and prevent unauthenticated access, organizational administrators must be uniquely identified and authenticated for all network management accesses to prevent potential misuse and compromise of the system. This means that there must be no shared accounts. The only exception is for the emergency administration account. Note: The number of emergency administration accounts is restricted to at least one, but no more than operationally required as determined by the ISSO.'
  desc 'check', 'Review the device configuration.

Enter the following command to view all administrative accounts:
show admin detail

If there are any shared accounts other than the emergency administration account, this is a finding.

Obtain the list of accounts configured on the authentication server.

If there are any shared accounts other than the emergency administration account, this is a finding.'
  desc 'fix', 'Do not configure any shared accounts, either on the A10 ADC itself or on the authentication servers. The only exception to this is the emergency administration account.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68609r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68049'
  tag rid: 'SV-82539r1_rule'
  tag stig_id: 'AADC-NM-000047'
  tag gtitle: 'SRG-APP-000148-NDM-000246'
  tag fix_id: 'F-74165r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
