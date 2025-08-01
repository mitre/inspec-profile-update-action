control 'SV-216395' do
  title 'The operating system must display the DoD approved system use notification message or banner before granting access to the system for general system logons.'
  desc 'Warning messages inform users who are attempting to log in to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. As implementing a logon banner to deter inappropriate use can provide a foundation for legal action against abuse, this warning content should be set as appropriate.'
  desc 'check', 'Review the contents of these two files and check that the proper DoD banner message is configured.

# cat /etc/motd
# cat /etc/issue

If the DoD-approved banner text is not in the files, this is a finding.'
  desc 'fix', 'The root role is required.

Edit the contents of these two files and ensure that the proper DoD banner message is viewable.

# pfedit /etc/motd
# pfedit /etc/issue

The DoD required text is:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17631r371273_chk'
  tag severity: 'low'
  tag gid: 'V-216395'
  tag rid: 'SV-216395r603267_rule'
  tag stig_id: 'SOL-11.1-050380'
  tag gtitle: 'SRG-OS-000023'
  tag fix_id: 'F-17629r371274_fix'
  tag 'documentable'
  tag legacy: ['SV-61081', 'V-48209']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
