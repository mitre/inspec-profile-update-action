control 'SV-223719' do
  title 'IBM z/OS Started Tasks must be properly identified and defined to RACF.'
  desc 'Started procedures have system generated job statements that do not contain the user, group, or password statements. To enable the started procedure to access the same protected resources that users and groups access, started procedures must have an associated USERID. If a USERID is not associated with the started procedure, the started procedure will not have access to the resources.'
  desc 'check', 'Refer to the site security plan, the system administrator, and system libraries to determine list of stated tasks available on the system.

If each Started task procedure identified has a unique associated userid or STC userids that is unique per product and function, this is not a finding.

If any of the following are untrue, this is a finding.

-All started task userids are connected to a valid STC group ID.
-Only userids associated with STCs are connected to STC group IDs.
-All STC userids are defined with the PROTECTED attribute.

From the ISPF Command Shell enter:
RL STARTED (Alternately execute RACF DSMON utility for the RACSPT report)

If all of the following is true, this is not a finding,

If any of the following is untrue, this is a finding.

-A generic catch all profile of ** is defined to the STARTED resource class.
-The STC group associated with the ** profile is not granted any explicit data set or resource access authorizations.
-The STC userid associated with the ** profile is not granted any explicit dataset or resource access authorizations and is defined with the RESTRICTED attribute.

Note: Execute the JCL in CNTL(IRRUT100) using the STC group associated with the ** profile as SYSIN input. This report lists all occurrences of this group within the RACF database, including data set and resource access lists.

Execute RACF utility DSMON RACSPT report.

If the ICHRIN03 started procedures table is not maintained to support recovery efforts in the event the STARTED resource class is deactivated or critical STC profiles are deleted, this is a finding.

If STCs critical to support this recovery effort (e.g., JES2, VTAM, TSO, etc.) are not maintained in ICHRIN03 to reflect the current STARTED resource class profiles, this is a finding.'
  desc 'fix', 'Define a RACF STARTED Class profile for each Started Proc that maps the proc to a unique userid, or STC userids will be unique per product and function if supported by vendor documentation. This can be accomplished with the sample command:
RDEF STARTED <procname>.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) STDATA(USER(<userid>) GROUP(<groupname>) TRACE(YES))

A corresponding USERID must be defined with appropriate authority. The "groupname" should be a valid STC group with no interactive users.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25392r572057_chk'
  tag severity: 'medium'
  tag gid: 'V-223719'
  tag rid: 'SV-223719r604139_rule'
  tag stig_id: 'RACF-ES-000720'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25380r571998_fix'
  tag 'documentable'
  tag legacy: ['SV-107249', 'V-98145']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
