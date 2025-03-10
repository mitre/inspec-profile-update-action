control 'SV-6430' do
  title 'Peer to Peer clients or utilities are installed.'
  desc 'File-sharing utilities and clients can provide the ability to share files with other users (Peer-to-Peer Sharing).  This type of utility is a security risk due to the potential risk of loss of sensitive data and the broadcast of the existence of a computer to others.  There are also many legal issues associated with these types of utilities including copyright infringement and intellectual property issues.  These types of utilities and clients include the following examples, Napster, Gnutella, Kazaa, and Freenet.

NOTE:  Clients used to access an internal or DoD controlled file-sharing system are permitted.'
  desc 'check', 'Procedure:  Using Windows explorer search for the following files:
*napv*.exe, Gnutella.exe

Criteria:  If any of the files are found examine it to determine if it is a file sharing utility.  If it is, this is a finding.'
  desc 'fix', 'Use Windows explorer to search for the files *napv.exe and Gnutella.exe.  If found and they are determined to be a file sharing utility, delete them.'
  impact 0.5
  ref 'DPMS Target Desktop Application - General'
  tag check_id: 'C-1041r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6357'
  tag rid: 'SV-6430r1_rule'
  tag stig_id: 'DTGW003'
  tag gtitle: 'DTGW003-Peer to Peer clients or utilities are inst'
  tag fix_id: 'F-5883r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
