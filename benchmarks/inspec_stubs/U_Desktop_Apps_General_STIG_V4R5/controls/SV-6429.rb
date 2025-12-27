control 'SV-6429' do
  title 'Public instant message clients are installed.'
  desc 'Instant Messaging or IM clients provide a way for a user to send a message to one or more other users in real time.  Additional capabilities may include file transfer and support for distributed game playing.  Communication between clients and associated directory services are managed through messaging servers.  Commercial IM clients include AOL Instant Messenger (AIM), MSN Messenger, and Yahoo! Messenger, and Skype.  The Windows XP operating system includes the Windows Messenger component as an IM client.  (This should not be confused with Windows Messaging which is a service within Windows.)

IM clients present a security issue when the clients route messages through public servers.  The obvious implication is that potentially sensitive information could be intercepted or altered in the course of transmission.  This same issue is associated with the use of public e-mail servers.

In order to reduce the potential for disclosure of sensitive Government information and to ensure the validity of official government information, IM clients that connect to public instant messaging services will not be installed. 

NOTE:  Clients used to access an internal or DoD controlled IM applications are permitted.'
  desc 'check', 'Procedure:  Using Windows explorer search for the following files:
ymsgr*.exe, aim.exe

Criteria:  If any of the files are found, this is a finding.
Note:  If the file is tied to an IM application that is DOD controlled, this is not a finding.'
  desc 'fix', 'Use Windows explorer to search for the files ymsgr*.exe and aim.exe.  If found, delete them unless the file is tied to an IM  application that is DoD controlled.'
  impact 0.5
  ref 'DPMS Target Desktop Application - General'
  tag check_id: 'C-1038r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6356'
  tag rid: 'SV-6429r1_rule'
  tag stig_id: 'DTGW002'
  tag gtitle: 'DTGW002-Public instant message clients are install'
  tag fix_id: 'F-5882r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
