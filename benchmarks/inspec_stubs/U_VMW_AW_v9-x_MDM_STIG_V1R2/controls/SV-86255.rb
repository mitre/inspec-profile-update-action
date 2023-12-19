control 'SV-86255' do
  title 'The AirWatch MDM Agent must be configured to alert via the trusted channel to the MDM server for the following event: failure to install an application from the MAS server.'
  desc 'Audit logs and alerts enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify when the security posture of the device is not as expected, including when critical or security relevant applications have not fully installed on mobile devices under management of the MDM platform. This enables the MDM administrator to take an appropriate remedial action.

SFR ID: FAU_ALT_EXT.2.1'
  desc 'check', 'Note: This procedure is the same as the procedure for VMAW-09-100080 and only has to be completed one time.

Review the AirWatch MDM Agent configuration settings and verify the Agent is configured to alert via the trusted channel to the MDM server for the following event: alert for failure to install an application.

On the AirWatch console complete the following procedure to ensure a Required Application List is created properly, and a conjunctive Compliance Policy is set to alert the Administrator (will additionally create an "Event" in the AirWatch console "Event Log"). There are two parts to this verification: 1) to verify that a Required Applications List was created properly, and 2) to verify that a conjunctive compliance policy is established: 

1. Log into the AirWatch MDM Administration console.
2. Choose "Apps and Books".
3. Choose "Application Settings".
4. Choose "App Groups".
5. Under "Name" column, click on appropriate App Group List. (Get a list of app groups from the MDM Administrator.)
6. Verify on "List" tab that all organization required applications and versions are listed.
7. Choose "Cancel".
8. Choose "Devices". 
9. Choose "Compliance Policies".
10. Choose "List View".
11. Under "Description" column, look for policy with the description of: "Application List".
12. Click on policy name.
13. On "Rules" tab, ensure boxes are selected for "Application List" and "Does Not Contain Required App(s)".
14. On "Actions" tab, ensure boxes are selected for "Notify", "Send Email to Administrator", and all organization assigned Administrators are listed in "To:" box (Note: With this set, the MDM Server Audit Function will also now record the Event automatically).

If under the "List" tab all organization required applications and versions are not listed; or on the "Rules" tab boxes are not selected for "Application List" and "Does Not Contain Required App(s)"; or on the "Actions" tab boxes are not selected for "Notify", "Send Email to Administrator", and all organization assigned Administrators are listed in "To:" box, this is a finding.'
  desc 'fix', %q(Configure the AirWatch MDM Agent to alert via the trusted channel to the MDM server for the following event: alert for failure to install an application.

On the AirWatch console complete the following procedure to create a Required Application List, and a conjunctive Compliance Policy that is set to Alert the Administrator (will additionally create "Event" in AirWatch console "Event Log"):

1. Log into the AirWatch MDM Administration console.
2. Choose "Apps and Books".
3. Choose "Application Settings".
4. Choose "App Groups".
5. Choose "Add Group".
6. Set "Type" to "Required" and select applicable "Platform". (i.e., iOS or Android)
7. Give Organization defined "Name" for list.
8. Choose "Add Application".
9. Enter Application Names and Application ID's as defined by the Organization.
10. Choose "Next".
11. Set "Assignment" criteria as necessary to include all Organization defined user and/or device groups.
12. Choose "Finish".
13. Choose "Devices". 
14. Choose "Compliance Policies".
15. Choose "List View".
16. Choose "Add".
17. Choose "Platform" (i.e., iOS or Android).
18. In "Rules" tab boxes, choose "Application List", and "Does Not Contain Required App(s)".
19. Choose "Next".
20. In "Actions" tab boxes, choose "Notify", "Send Email to Administrator", and enter Organization defined Administrators in "To:" box.
21. Choose "Next".
22. Add "Assigned Groups" of users/devices as defined by the Organization.
23. Choose "Next".
24. Choose "Finish and Activate".)
  impact 0.5
  ref 'DPMS Target AirWatch MDM 9.x'
  tag check_id: 'C-71961r4_chk'
  tag severity: 'medium'
  tag gid: 'V-71631'
  tag rid: 'SV-86255r1_rule'
  tag stig_id: 'VMAW-09-100060'
  tag gtitle: 'PP-MDM-202005'
  tag fix_id: 'F-77957r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
