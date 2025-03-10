control 'SV-104233' do
  title 'Symantec ProxySG must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following.

By default, the ProxySG operates as an un-authenticated proxy. Authentication of users must be explicitly configured as described here and in in the ProxySG Administration Guide, Chapter 49: Controlling Access to the Internet and Intranet.'
  desc 'check', 'Verify that ProxySG is uniquely identifying organizational users.

1. Log on to the Web Management Console. 
2. Browse to Configuration >> Authentication >> Windows Domain.
3. Verify that a domain is listed in the Domains field and indicates "Joined and Used".

If Symantec ProxySG does not uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users), this is a finding.'
  desc 'fix', 'Configure the ProxySG to perform unique identification of organizational users.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication >> Windows Domain.
3. Click "Add New Domain" and follow prompts to join the Windows Domain.'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93465r1_chk'
  tag severity: 'high'
  tag gid: 'V-94279'
  tag rid: 'SV-104233r1_rule'
  tag stig_id: 'SYMP-AG-000320'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag fix_id: 'F-100395r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
