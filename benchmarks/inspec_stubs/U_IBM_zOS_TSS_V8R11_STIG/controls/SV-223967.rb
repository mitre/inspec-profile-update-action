control 'SV-223967' do
  title 'The CA-TSS BYPASS attribute must be limited to trusted STCs only.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST(STC)

If only STCs listed as trusted in the IBM z/OS MVS Initialization and Tuning Reference are granted the BYPASS privilege, this is not a finding.

Guidelines for reference:

 Assign the TRUSTED attribute when one of the following conditions applies:
-The started procedure or address space creates or accesses a wide variety of unpredictably named data sets within your installation.
-Insufficient authority to an accessed resource might risk an unsuccessful IPL or other system problem.
-Avoid assigning TRUSTED to a z/OS started procedure or address space unless it is listed here or you are instructed to do so by the product documentation.

Additionally external security managers are candidates for trusted attribute. Any other started tasks not listed or not covered by the guidelines are a finding unless approval by the Authorizing Official AO.'
  desc 'fix', 'Review the STC record for ACIDs with the BYPASS attribute. Ensure only those trusted STCs that are listed in the IBM z/OS MVS Initialization and Tuning Reference, have been granted this authority. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes.

Trusted STCs:

While the actual list may vary based on local site requirements and software configuration, the started tasks listed in the IBM z/OS MVS Initialization and Tuning Reference is an approved list of started tasks that may be considered trusted started procedures.

Guidelines for reference:

 Assign the TRUSTED attribute when one of the following conditions applies:
-The started procedure or address space creates or accesses a wide variety of unpredictably named data sets within your installation.
-Insufficient authority to an accessed resource might risk an unsuccessful IPL or other system problem.
-Avoid assigning TRUSTED to a z/OS started procedure or address space unless it is listed here or you are instructed to do so by the product documentation.

Additionally external security managers are candidates for trusted attribute. Any other started tasks not; listed or not covered by the guidelines are a finding unless approval by the Authorizing Official AO.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25640r516300_chk'
  tag severity: 'high'
  tag gid: 'V-223967'
  tag rid: 'SV-223967r877808_rule'
  tag stig_id: 'TSS0-ES-000940'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25628r516301_fix'
  tag 'documentable'
  tag legacy: ['SV-107745', 'V-98641']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
