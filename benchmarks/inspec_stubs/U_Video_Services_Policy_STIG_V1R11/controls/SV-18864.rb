control 'SV-18864' do
  title 'A VTU password must be used for each VTU function.'
  desc 'Passwords are required for access control to various functions provided by a VTU. The following is a list of possible functions: 
1. Local user device use/activation (not typically supported).
2. Local user call accounting code.
3. Local user access to user configurable settings.
4. Local user or machine access from the VTU to the user’s networked or otherwise attached PC running a presentation or desktop sharing application (or vice versa i.e., PC to VTU) (discussed later).
5. Local administrator access to configuration settings.
6. Remote administrator access to configuration settings.
7. Remote/centralized VTU management/control system access to the VTU (identifies the management server to the VTU, alternately restricted by IP address).
8. Remote caller access to a VTU integrated MCU conference without local user intervention.
9. Remote user access to media streamed from a VTU CODEC.
10. Local VTU access to a centralized MCU for joining conferences hosted remotely (i.e., the password sent to the remote MCU).
11. Local VTU access to gatekeeper services (automatically identifies the VTU to the gatekeeper).

The passwords or PINs used for various differing functions must be logically grouped and be unique among other passwords implemented on the system. For example, local user password/PINs such as those in items 1, 2, and 3 could be the same. These would be entered manually using the hand-held remote control. Another logical grouping might be items 10 and 11. The other functions are logically separate because they perform different functions and are used by different entities. One vendor uses a single password pre-configured in the VTU for functions 8 (bi-directionally), 9, 10 and possibly 11. This is a problem for two reasons. The first was stated above, it is used for different functions, and secondly, it is preprogrammed into the VTU. While a VTU can have an identity or password that identifies itself to another machine for passing control information, such a password cannot be used to provide user level access to information. The user must enter this password manually. A VTC related application of machine to machine authentication would be the VTU identifying itself to a gateway or a centralized VTU management or control system to a VTU.'
  desc 'check', 'Review site documentation to confirm passwords are required for access to all functions and services of the VTU, to include: 
 - Local user device use/activation and access to user configurable settings.
 - Local user or machine access to the user’s networked or otherwise attached PC running a presentation or desktop sharing application when permitted.
 - Local administrator access to configuration settings.
 - Remote administrator access to configuration settings and for remote software or firmware upgrade.
 - Remote caller access to a VTU integrated MCU conference if local user intervention is not required. 
 - Remote user access to media streamed from a VTU CODEC.
 - Passwords used by VTU users, administrators, and devices are logically grouped by entity and roles (human or machine), type of access provided (information vs. control), and device accessed.
 - Passwords are unique across these logical groups. (i.e., a single password will not be used for multiple functions or to access multiple devices from a given VTU with the exception of a user’s local access to the VTU or its user accessible settings).
 - Passwords that provide user or administrator level access to another device or information will not be stored on the VTU for automated entry in lieu of the person entering the required password. 

If a VTU password is not used for each VTU function, this is a finding. If different VTU passwords are not used for groups of VTU functions, this is a finding.'
  desc 'fix', 'Implement VTUs that support different password for different functions as follows: 
- Passwords are required for access to all functions and services of the VTU. This includes, but may not be limited to, the following: 
- Local user device use/activation and access to user configurable settings. 
- Local user or machine access to the user’s networked or otherwise attached PC running a presentation or desktop sharing application (if used or permitted; discussed later under PC Data and Presentation Sharing).
- Local administrator access to configuration settings.
- Remote administrator access to configuration settings and for remote software or firmware upgrade via IP or ISDN.
- Remote caller access to a VTU integrated MCU conference if local user intervention is not required. 
- Remote user access to media streamed from a VTU CODEC.
- Passwords used by VTU users, administrators, and devices are logically grouped by entity and roles (human or machine), type of access provided (information vs. control), and device accessed.
- Passwords are unique across these logical groups (i.e., a single password will not be used for multiple functions or to access multiple devices from a given VTU with the exception of a user’s local access to the VTU or its user accessible settings).
- Passwords that provide user or administrator level access to another device or information will not be stored on the VTU for automated entry in lieu of the person entering the required password.

Note: Updating firmware or software to provide desired functionality is preferred. A vendor may provide security updates and patches that offer additional functions.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18960r4_chk'
  tag severity: 'medium'
  tag gid: 'V-17690'
  tag rid: 'SV-18864r4_rule'
  tag stig_id: 'RTS-VTC 2026.00'
  tag gtitle: 'RTS-VTC 2026'
  tag fix_id: 'F-17587r3_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Other']
end
