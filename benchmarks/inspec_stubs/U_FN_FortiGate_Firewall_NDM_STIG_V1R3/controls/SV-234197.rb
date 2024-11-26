control 'SV-234197' do
  title 'FortiGate devices performing maintenance functions must restrict use of these functions to authorized personnel only.'
  desc 'There are security-related issues arising from software brought into the network device specifically for diagnostic and repair actions (e.g., a software packet sniffer installed on a device to troubleshoot system traffic, or a vendor installing or running a diagnostic application to troubleshoot an issue with a vendor-supported device). If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system.

This requirement addresses security-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational network devices. Maintenance tools can include hardware, software, and firmware items. Maintenance tools are potential vehicles for transporting malicious code, either intentionally or unintentionally, into a facility and subsequently into organizational information systems. Maintenance tools can include, for example, hardware/software diagnostic test equipment and hardware/software packet sniffers. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege:

1. Click System.
2. Click Administrators.
3. Identify the administrator designated to perform maintenance functions and hover over the profile assigned to the role.
4. Click Edit.
5. Verify the permission to System is set to Read/Write or Custom with Maintenance set to Read/Write.

If an authorized administrator does not have Read/Write access to System Maintenance Settings, this is a finding.

Then,
1. Click System.
2. Click Administrators.
3. Click all other low-privileged administrators and hover over the profile assigned to the role.
4. Click Edit.
5. Verify the permission to System Maintenance is customized set to Read or None.

If any low-privileged administrator has Read/Write access to System Settings, this is a finding.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command for all low privileged admin user:
     # show system admin  {ADMIN NAME}  | grep -i accprofile
The output should be:  
           set accprofile {PROFILE NAME}

Use the profile name from the output result of above command. 
     # show system accprofile {PROFILE NAME} | grep -i sysgrp
The output should be:  
          set sysgrp read
or
         set sysgrp none
          
If any low privileged admin user has sysgrp parameter set to value Read/Write, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

First, set one admin profile with access to System Maintenance.
1. Click System.
2. Click Admin Profiles.
3. Click +Create New (Admin Profile).
4. Assign a meaningful name to the Profile.
5. Set System Access Permissions to Read/Write or Custom with Maintenance set to Read/Write.
6. Click OK to save this Profile.

Then, 
1. Click System.
2. Click Administrators.
3. Click +Create New (Administrator).
4. Configure Administrator settings with unique Username, Type, and Password.
5. Assign the Administrator Profile that was configured above.
6. Click OK to save.

Note: Do not assign this admin profile to any other users other than the authorized administrator.

To limit the System access to existing low-privilege administrators: 

1. Click System.
2. Click Administrators.
3. Identify the admin role that has unauthorized access to System settings.
4. Select the admin role and hover over the profile assigned to the role.
5. Click Edit.
6. On System access permission, click Read or None.
7. Click OK to save.

Repeat this process to define all the Administrators needed to meet privilege separation requirements for the organization.

or 

1.  Open a CLI console, via SSH or available from the GUI
2. First edit the admin profile by running the following command:

     # config system accprofile 
     #    edit {PROFILE NAME}
     #    set sysgrp read or none
     #    next
     #    end
Then, assign this admin profile to the authorized administrator account. 
     # config system admin  
     #    edit {ADMIN NAME}
     #    set accprofile  {PROFILE NAME}
     #    next
     # end
Note: Do not assign this admin profile to any other users other than the authorized administrator.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37382r850528_chk'
  tag severity: 'medium'
  tag gid: 'V-234197'
  tag rid: 'SV-234197r850529_rule'
  tag stig_id: 'FGFW-ND-000190'
  tag gtitle: 'SRG-APP-000408-NDM-000314'
  tag fix_id: 'F-37347r611779_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002883']
  tag nist: ['CM-6 b', 'MA-3 (4)']
end
