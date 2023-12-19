control 'SV-224102' do
  title 'The IBM z/OS UNIX Telnet server Startup parameters must be properly specified.'
  desc %q(Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read & consent to terms in IS user agreem't.")
  desc 'check', 'From the ISPF Command Shell enter:
ISHELL

Enter /etc/ for a pathname - you may need to issue a CD /etc/
select FILE NAME inetd.conf

If Option -D login is included on the otelnetd command, this is not a finding.

If Option -c 900 is included on the otelnetd command, this is not a finding.

NOTE: "900" indicates a session timeout value of "15" minutes and is currently the maximum value allowed.'
  desc 'fix', 'Configure the startup parameters in the inetd.conf file for otelnetd to conform to the specifications below.

The otelnetd startup command includes the options -D login and -c 900, where:

-D login indicates that messages should be written to the syslogd facility for login and logout activity.

-c 900 indicates that the Telnet session should be terminated after "15" minutes of inactivity.

NOTE: "900" is the maximum value; any value between "1" and "900" is acceptable.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25775r516705_chk'
  tag severity: 'medium'
  tag gid: 'V-224102'
  tag rid: 'SV-224102r561402_rule'
  tag stig_id: 'TSS0-UT-000040'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-25763r516706_fix'
  tag 'documentable'
  tag legacy: ['V-98911', 'SV-108015']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
