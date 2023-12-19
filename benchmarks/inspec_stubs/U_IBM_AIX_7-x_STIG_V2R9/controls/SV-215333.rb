control 'SV-215333' do
  title 'AIX must use Trusted Execution (TE) Check policy.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Run the following command to show the current status of the "TE", "CHKEXEC", and "CHKKERNEXT" on the system:
# trustchk -p 2>&1 | egrep -e "TE=|CHKEXEC|CHKKERNEXT"

The above command should yield the following output:
TE=ON
CHKEXEC=ON
CHKKERNEXT=ON

If "TE", "CHKEXEC", or "CHKKERNEXT" is "OFF", this is a finding.'
  desc 'fix', 'Run the following command to turn on the all parts of Trusted Execution (TE):
# trustchk -p TE=on CHKEXEC=on CHKKERNEXT=on'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16531r294450_chk'
  tag severity: 'medium'
  tag gid: 'V-215333'
  tag rid: 'SV-215333r853482_rule'
  tag stig_id: 'AIX7-00-003020'
  tag gtitle: 'SRG-OS-000312-GPOS-00124'
  tag fix_id: 'F-16529r294451_fix'
  tag 'documentable'
  tag legacy: ['V-91509', 'SV-101607']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
