control 'SV-223902' do
  title 'CA-TSS must limit WRITE or greater access to LINKLIST libraries to system programmers only.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.

'
  desc 'check', 'From any ISPF input line, enter TSO ISRDDN LINKLIST.

If all of the following are untrue, this is not a finding.

If any of the following is true, this is a finding.

The ACP data set rules for LINKLIST libraries do not restrict WRITE or greater access to only z/OS systems programming personnel.

The ACP data set rules for LINKLIST libraries do not specify that all (i.e., failures and successes) WRITE or greater access will be logged.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect the LINKLIST libraries.

Configure the WRITE or greater access to LINKLIST libraries to be limited to system programmers only and all WRITE or greater access is logged.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25575r516105_chk'
  tag severity: 'medium'
  tag gid: 'V-223902'
  tag rid: 'SV-223902r877743_rule'
  tag stig_id: 'TSS0-ES-000290'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25563r516106_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98511', 'SV-107615']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
