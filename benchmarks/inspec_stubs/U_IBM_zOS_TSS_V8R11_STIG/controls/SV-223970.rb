control 'SV-223970' do
  title 'CA-TSS ACIDs defined as security administrators must have the NOATS attribute.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Execute TSS Report TSS AUDIT with PRIVILEGES control statement PRIVILEGES [SHORT]. For more information TSSAUDIT reports refer to the CA-TSS Report and Tracking Guide. Refer to the resulting report.

If all security administrators have the "NOATS" attribute, this is not a finding.'
  desc 'fix', %q(Review all security administrator ACIDs. Ensure the "NOATS" attribute has been assigned. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes.

NOTE: The NOATS attribute may be added to an ACID or an ACID's PROFILE.

The following command may be issued to determine if the NOATS attribute is defined to an ACID or an ACID's PROFILE:
tss list(<acid>) data(basic,profile))
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25643r516309_chk'
  tag severity: 'medium'
  tag gid: 'V-223970'
  tag rid: 'SV-223970r877811_rule'
  tag stig_id: 'TSS0-ES-000970'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25631r516310_fix'
  tag 'documentable'
  tag legacy: ['SV-107751', 'V-98647']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
