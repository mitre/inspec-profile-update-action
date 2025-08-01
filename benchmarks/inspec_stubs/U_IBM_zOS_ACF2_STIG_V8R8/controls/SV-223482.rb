control 'SV-223482' do
  title 'ACF2 LOGONIDs with the NON-CNCL attribute specified in the associated LOGONID record must be listed as trusted and must be specifically approved.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during business hours can indicate hostile activity if it occurs during off hours.

Depending on mission needs and conditions, account usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the operating system must be configured to enforce the specific conditions or circumstances under which organization-defined accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).'
  desc 'check', 'From the ACF command screen enter:
SET LID 
SET VERBOSE 
LIST IF(NON-CNCL)

If only logonids associated with trusted STCs have the NON-CNCL attribute specified, this is not a finding.

TRUSTED STCs:
STCs that are listed as z/OS started tasks and address spaces in the IBM z/OS MVS Initialization and Tuning Reference. 

Guidelines for reference:

Assign the TRUSTED attribute when one of the following conditions applies:
-The started procedure or address space creates or accesses a wide variety of unpredictably named data sets within your installation.
-Insufficient authority to an accessed resource might risk an unsuccessful IPL or other system problem.
-Avoid assigning TRUSTED to a z/OS started procedure or address space unless it is listed here or you are instructed to do so by the product documentation.

Additionally external security managers are candidates for trusted attribute.
 
Any other started tasks not listed or not covered by the guidelines are a finding unless approval by the Authorizing Official AO.'
  desc 'fix', 'Review all LOGONIDs with the NON-CNCL attribute. Ensure that only STCs in the trusted list in the IBM z/OS MVS Initialization and Tuning Reference have been granted this authority. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes.

Trusted STCs:
While the actual list may vary based on local site requirements and software configuration, the started tasks listed in the IBM z/OS MVS Initialization and Tuning Reference is an approved list of started tasks that may be considered trusted started procedures.

Guidelines for reference:
Assign the TRUSTED attribute when one of the following conditions applies:
-The started procedure or address space creates or accesses a wide variety of unpredictably named data sets within your installation.
-Insufficient authority to an accessed resource might risk an unsuccessful IPL or other system problem.
-Avoid assigning TRUSTED to a z/OS started procedure or address space unless it is listed here or you are instructed to do so by the product documentation.

Additionally external security managers are candidates for trusted attribute. Any other started tasks not listed or not covered by the guidelines are a finding unless approval by the Authorizing Official AO.

These STCs will be given the following attribute to facilitate access while logging any accesses they would not ordinarily be granted by the access rule sets:

NON-CNCL

Example:
SET LID
CHANGE logonid STC NON-CNCL'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25155r504555_chk'
  tag severity: 'medium'
  tag gid: 'V-223482'
  tag rid: 'SV-223482r533198_rule'
  tag stig_id: 'ACF2-ES-000640'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25143r504556_fix'
  tag 'documentable'
  tag legacy: ['SV-106767', 'V-97663']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
