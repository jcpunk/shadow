"""
Test usermod
"""

from __future__ import annotations

import pytest
from pytest_mh.conn import ProcessError

from framework.roles.shadow import Shadow
from framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.Shadow)
def test_usermod__rename_user(shadow: Shadow):
    """
    :title: Rename user
    :setup:
        1. Create user
        2. Rename user
    :steps:
        1. Check passwd entry
        2. Check shadow entry
        3. Check group entry
        4. Check gshadow entry
        5. Check home folder
    :expectedresults:
        1. passwd entry for the user exists and the attributes are correct
        2. shadow entry for the user exists and the attributes are correct
        3. group entry for the user exists and the attributes are correct
        4. gshadow entry for the user exists and the attributes are correct
        5. Home folder exists
    :customerscenario: False
    """
    shadow.useradd("tuser1")
    shadow.usermod("-l tuser2 tuser1")

    passwd_entry = shadow.tools.getent.passwd("tuser2")
    assert passwd_entry is not None, "User should be found"
    assert passwd_entry.name == "tuser2", "Incorrect username"
    assert passwd_entry.uid == 1000, "Incorrect UID"

    shadow_entry = shadow.tools.getent.shadow("tuser2")
    assert shadow_entry is not None, "User should be found"
    assert shadow_entry.name == "tuser2", "Incorrect username"

    group_entry = shadow.tools.getent.group("tuser1")
    assert group_entry is not None, "Group should be found"
    assert group_entry.name == "tuser1", "Incorrect groupname"
    assert group_entry.gid == 1000, "Incorrect GID"

    if shadow.host.features["gshadow"]:
        gshadow_entry = shadow.tools.getent.gshadow("tuser1")
        assert gshadow_entry is not None, "User should be found"
        assert gshadow_entry.name == "tuser1", "Incorrect username"

    assert shadow.fs.exists("/home/tuser1"), "Home folder should be found"


@pytest.mark.topology(KnownTopology.Shadow)
@pytest.mark.parametrize(
    "expiration_date, expected_date",
    [
        ("0", 0),  # 1970-01-01
        ("1", 1),  # 1970-01-02
        ("20089", 20089),  # 2025-01-01
        ("1000000", 1000000),  # This will happen in a very long time
        ("1970-01-01", 0),
        ("1970-01-02", 1),
        ("2025-01-01", 20089),
    ],
)
def test_usermod__set_expire_date_with_valid_date(shadow: Shadow, expiration_date: str, expected_date: int | None):
    """
    :title: Set valid account expiration date
    :setup:
        1. Create user
    :steps:
        1. Set valid account expiration date
        2. Check user exists and expiration date
    :expectedresults:
        1. The expiration date is correctly set
        2. User is found and expiration date is valid
    :customerscenario: False
    """
    shadow.useradd("tuser1")

    shadow.usermod(f"-e {expiration_date} tuser1")

    result = shadow.tools.getent.shadow("tuser1")
    assert result is not None, "User should be found"
    assert result.name == "tuser1", "Incorrect username"
    assert result.expiration_date == expected_date, "Incorrect expiration date"


@pytest.mark.topology(KnownTopology.Shadow)
@pytest.mark.parametrize(
    "expiration_date",
    [
        "-2",  # Dates can't be in negative numbers
        "-1000",  # Dates can't be in negative numbers
        "2025-18-18",  # That month and day don't exist
        "1969-01-01",  # This is before 1970-01-01
        "2025-13-01",  # That month doesn't exist
        "2025-01-32",  # That day doesn't exist
        "today",
        "tomorrow",
    ],
)
def test_usermod__set_expire_date_with_invalid_date(shadow: Shadow, expiration_date: str):
    """
    :title: Set invalid account expiration date
    :setup:
        1. Create user
    :steps:
        1. Set invalid account expiration date
        2. Check user exists and expiration date
    :expectedresults:
        1. The process fails and the expiration date isn't changed
        2. User is found and expiration date is empty
    :customerscenario: False
    """
    shadow.useradd("tuser1")

    with pytest.raises(ProcessError):
        shadow.usermod(f"-e {expiration_date} tuser1")

    result = shadow.tools.getent.shadow("tuser1")
    assert result is not None, "User should be found"
    assert result.name == "tuser1", "Incorrect username"
    assert result.expiration_date is None, "Expiration date should be empty"


@pytest.mark.topology(KnownTopology.Shadow)
@pytest.mark.parametrize(
    "expiration_date",
    [
        "-1",
        "''",
    ],
)
def test_usermod__set_expire_date_with_empty_date(shadow: Shadow, expiration_date: str):
    """
    :title: Set empty account expiration date
    :setup:
        1. Create user
    :steps:
        1. Set account expiration date
        2. Check user exists and expiration date
        3. Empty account expiration date
        4. Check user exists and expiration date
    :expectedresults:
        1. The expiration date is correctly set
        2. User is found and expiration date is valid
        3. The expiration date is correctly emptied
        4. User is found and expiration date is empty
    :customerscenario: False
    """
    shadow.useradd("tuser1")

    shadow.usermod("-e 10 tuser1")

    result = shadow.tools.getent.shadow("tuser1")
    assert result is not None, "User should be found"
    assert result.name == "tuser1", "Incorrect username"
    assert result.expiration_date == 10, "Incorrect expiration date"

    shadow.usermod(f"-e {expiration_date} tuser1")

    result = shadow.tools.getent.shadow("tuser1")
    assert result is not None, "User should be found"
    assert result.name == "tuser1", "Incorrect username"
    assert result.expiration_date is None, "Expiration date should be empty"


@pytest.mark.topology(KnownTopology.Shadow)
def test_usermod__change_shell(shadow: Shadow):
    """
    :title: Change user login shell
    :description:
        Changing only the login shell should succeed without locking
        shadow, group, or subordinate ID files.
    :setup:
        1. Create user with default shell
    :steps:
        1. Change user shell
        2. Check passwd entry for updated shell
        3. Check shadow entry is unchanged
    :expectedresults:
        1. usermod succeeds
        2. passwd entry shows new shell
        3. shadow entry is still present and unchanged
    :customerscenario: False
    """
    shadow.useradd("tuser1")
    shadow.usermod("-s /bin/sh tuser1")

    passwd_entry = shadow.tools.getent.passwd("tuser1")
    assert passwd_entry is not None, "User should be found"
    assert passwd_entry.name == "tuser1", "Incorrect username"
    assert passwd_entry.shell == "/bin/sh", "Shell should be updated"

    shadow_entry = shadow.tools.getent.shadow("tuser1")
    assert shadow_entry is not None, "Shadow entry should still exist"
    assert shadow_entry.name == "tuser1", "Incorrect shadow username"


@pytest.mark.topology(KnownTopology.Shadow)
def test_usermod__change_uid(shadow: Shadow):
    """
    :title: Change user UID
    :description:
        Changing UID should lock passwd, shadow, group, and subordinate
        ID files since UID changes can affect multiple databases.
    :setup:
        1. Create user
    :steps:
        1. Change user UID
        2. Check passwd entry for updated UID
        3. Check shadow entry is intact
        4. Check group entry is intact
    :expectedresults:
        1. usermod succeeds
        2. passwd entry shows new UID
        3. shadow entry is still present
        4. group entry is still present
    :customerscenario: False
    """
    shadow.useradd("tuser1")
    shadow.usermod("-u 5555 tuser1")

    passwd_entry = shadow.tools.getent.passwd("tuser1")
    assert passwd_entry is not None, "User should be found"
    assert passwd_entry.name == "tuser1", "Incorrect username"
    assert passwd_entry.uid == 5555, "UID should be updated"

    shadow_entry = shadow.tools.getent.shadow("tuser1")
    assert shadow_entry is not None, "Shadow entry should still exist"
    assert shadow_entry.name == "tuser1", "Incorrect shadow username"

    group_entry = shadow.tools.getent.group("tuser1")
    assert group_entry is not None, "Group should still exist"


@pytest.mark.topology(KnownTopology.Shadow)
def test_usermod__change_primary_group(shadow: Shadow):
    """
    :title: Change user primary group
    :description:
        Changing primary group should lock passwd and group files.
    :setup:
        1. Create user and a new group
    :steps:
        1. Change user's primary group
        2. Check passwd entry for updated GID
        3. Check new group entry exists
    :expectedresults:
        1. usermod succeeds
        2. passwd entry shows new GID
        3. Group entry exists
    :customerscenario: False
    """
    shadow.useradd("tuser1")
    shadow.groupadd("tgroup1")

    group_entry = shadow.tools.getent.group("tgroup1")
    assert group_entry is not None, "Group should be found"

    shadow.usermod(f"-g {group_entry.gid} tuser1")

    passwd_entry = shadow.tools.getent.passwd("tuser1")
    assert passwd_entry is not None, "User should be found"
    assert passwd_entry.gid == group_entry.gid, "Primary GID should be updated"


@pytest.mark.topology(KnownTopology.Shadow)
def test_usermod__change_comment(shadow: Shadow):
    """
    :title: Change user GECOS comment
    :description:
        Changing only the GECOS comment should succeed without locking
        shadow, group, or subordinate ID files.
    :setup:
        1. Create user
    :steps:
        1. Change user comment
        2. Check passwd entry for updated comment
    :expectedresults:
        1. usermod succeeds
        2. passwd entry shows new comment
    :customerscenario: False
    """
    shadow.useradd("tuser1")
    shadow.usermod('-c "Test User" tuser1')

    passwd_entry = shadow.tools.getent.passwd("tuser1")
    assert passwd_entry is not None, "User should be found"
    assert passwd_entry.gecos == "Test User", "Comment should be updated"


@pytest.mark.topology(KnownTopology.Shadow)
def test_usermod__change_home_directory(shadow: Shadow):
    """
    :title: Change user home directory
    :description:
        Changing only the home directory should succeed without locking
        shadow, group, or subordinate ID files.
    :setup:
        1. Create user
    :steps:
        1. Change user home directory
        2. Check passwd entry for updated home directory
    :expectedresults:
        1. usermod succeeds
        2. passwd entry shows new home directory
    :customerscenario: False
    """
    shadow.useradd("tuser1")
    shadow.usermod("-d /home/newhome tuser1")

    passwd_entry = shadow.tools.getent.passwd("tuser1")
    assert passwd_entry is not None, "User should be found"
    assert passwd_entry.home == "/home/newhome", "Home directory should be updated"


@pytest.mark.topology(KnownTopology.Shadow)
def test_usermod__change_inactive_days(shadow: Shadow):
    """
    :title: Change user password inactivity period
    :description:
        Changing the inactivity period requires locking shadow file
        since it is a shadow-specific field.
    :setup:
        1. Create user
    :steps:
        1. Change user inactivity period
        2. Check shadow entry for updated inactivity days
    :expectedresults:
        1. usermod succeeds
        2. shadow entry shows new inactivity days
    :customerscenario: False
    """
    shadow.useradd("tuser1")
    shadow.usermod("-f 30 tuser1")

    shadow_entry = shadow.tools.getent.shadow("tuser1")
    assert shadow_entry is not None, "Shadow entry should exist"
    assert shadow_entry.name == "tuser1", "Incorrect shadow username"
    assert shadow_entry.inactivity_days == 30, "Inactivity days should be updated"


@pytest.mark.topology(KnownTopology.Shadow)
def test_usermod__rename_user_with_secondary_group(shadow: Shadow):
    """
    :title: Rename user who is a member of a secondary group
    :description:
        Renaming a user should lock passwd, shadow, group, and
        subordinate ID files. Group membership should be updated
        to reflect the new username.
    :setup:
        1. Create user and a secondary group
        2. Add user to secondary group
    :steps:
        1. Rename user
        2. Check passwd entry for new name
        3. Check shadow entry for new name
        4. Check secondary group still lists user under new name
    :expectedresults:
        1. usermod succeeds
        2. passwd entry shows new name
        3. shadow entry shows new name
        4. Secondary group membership updated to new name
    :customerscenario: False
    """
    shadow.useradd("tuser1")
    shadow.groupadd("tgroup1")
    shadow.usermod("-G tgroup1 tuser1")

    shadow.usermod("-l tuser2 tuser1")

    passwd_entry = shadow.tools.getent.passwd("tuser2")
    assert passwd_entry is not None, "User should be found with new name"
    assert passwd_entry.name == "tuser2", "Incorrect username"

    shadow_entry = shadow.tools.getent.shadow("tuser2")
    assert shadow_entry is not None, "Shadow entry should exist with new name"
    assert shadow_entry.name == "tuser2", "Incorrect shadow username"

    group_entry = shadow.tools.getent.group("tgroup1")
    assert group_entry is not None, "Secondary group should still exist"
    assert "tuser2" in group_entry.members, "New username should be in group members"
    assert "tuser1" not in group_entry.members, "Old username should not be in group members"


@pytest.mark.topology(KnownTopology.Shadow)
def test_usermod__change_uid_preserves_group_membership(shadow: Shadow):
    """
    :title: Change UID preserves group membership
    :description:
        Changing UID should lock group files for consistency. Group
        membership should be preserved after UID change.
    :setup:
        1. Create user and a secondary group
        2. Add user to secondary group
    :steps:
        1. Change user UID
        2. Check passwd entry for updated UID
        3. Check group membership is preserved
    :expectedresults:
        1. usermod succeeds
        2. passwd entry shows new UID
        3. Group membership is unchanged
    :customerscenario: False
    """
    shadow.useradd("tuser1")
    shadow.groupadd("tgroup1")
    shadow.usermod("-G tgroup1 tuser1")

    shadow.usermod("-u 7777 tuser1")

    passwd_entry = shadow.tools.getent.passwd("tuser1")
    assert passwd_entry is not None, "User should be found"
    assert passwd_entry.uid == 7777, "UID should be updated"

    group_entry = shadow.tools.getent.group("tgroup1")
    assert group_entry is not None, "Group should still exist"
    assert "tuser1" in group_entry.members, "User should still be in group"
