control 'SV-16812' do
  title 'No logon warning banner is configured for VirtualCenter users.'
  desc 'Once users are authenticated by VirtualCenter, users should be presented with a warning message. presenting a warning message prior to user logon may assist the prosecution of trespassers on the computer system. Guidelines published by the US Department of Defense require that warning messages include at least the name of the organization that owns the system, the system is subject to monitoring and that such monitoring is in compliance with local statutes, and that use of the system implies consent to such monitoring.'
  desc 'check', "1. Log into VirtualCenter with the VI Client.
2. Select the Administration Menu at the top of the page.
3. Select the Edit Message of the Day.
4. Review the contents and verify the following are listed: 

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USGauthorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content ofprivileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
OK

OR

I've read & consent to terms in IS user agreem't.

If the banner does not contain these items, this is a finding."
  desc 'fix', 'Configure a logon banner in VirtualCenter.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16228r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15871'
  tag rid: 'SV-16812r1_rule'
  tag stig_id: 'ESX0720'
  tag gtitle: 'VirtualCenter has no logon warning banner.'
  tag fix_id: 'F-15831r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
