import React from "react";
import { render, screen, getDefaultNormalizer } from "@testing-library/react";

import createMockActivity from "__mocks__/activityMock";
import createMockQuery from "__mocks__/queryMock";
import { createMockTeamSummary } from "__mocks__/teamMock";
import { ActivityType } from "interfaces/activity";

import ActivityItem from ".";

const getByTextContent = (text: string) => {
  return screen.getByText((content, element) => {
    if (!element) {
      return false;
    }
    const hasText = (thisElement: Element) => thisElement.textContent === text;
    const elementHasText = hasText(element);
    const childrenDontHaveText = Array.from(element?.children || []).every(
      (child) => !hasText(child)
    );
    return elementHasText && childrenDontHaveText;
  });
};

describe("Activity Feed", () => {
  it("renders avatar, actor name, timestamp", async () => {
    const currentDate = new Date();
    currentDate.setDate(currentDate.getDate() - 2);

    const activity = createMockActivity({
      created_at: currentDate.toISOString(),
    });

    render(<ActivityItem activity={activity} isPremiumTier />);

    // waiting for the activity data to render
    await screen.findByText("Test User");

    expect(screen.getByRole("img")).toHaveAttribute("alt", "User avatar");
    expect(screen.getByText("Test User")).toBeInTheDocument();
    expect(screen.getByText("2 days ago")).toBeInTheDocument();
  });

  it("renders a default activity for activities without a specific message", () => {
    const activity = createMockActivity({
      type: ActivityType.CreatedPack,
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(screen.getByText("created pack.")).toBeInTheDocument();
  });

  it("renders a default activity for activities with a named property", () => {
    const activity = createMockActivity({
      type: ActivityType.CreatedPack,
      details: { pack_name: "Test pack" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(screen.getByText("created pack .")).toBeInTheDocument();
    expect(screen.getByText("Test pack")).toBeInTheDocument();
  });

  it("renders a live_query type activity", () => {
    const activity = createMockActivity({ type: ActivityType.LiveQuery });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(screen.getByText("ran a live query .")).toBeInTheDocument();
  });

  it("renders a live_query type activity with host count details", () => {
    const activity = createMockActivity({
      type: ActivityType.LiveQuery,
      details: {
        targets_count: 10,
      },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("ran a live query on 10 hosts.")
    ).toBeInTheDocument();
  });

  it("renders a live_query type activity for a saved live query with targets", () => {
    const activity = createMockActivity({
      type: ActivityType.LiveQuery,
      details: {
        query_name: "Test Query",
        query_sql: "SELECT * FROM users",
      },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("ran the query as a live query .")
    ).toBeInTheDocument();
    expect(screen.getByText("Test Query")).toBeInTheDocument();
    expect(screen.getByText("Show query")).toBeInTheDocument();
  });

  it("renders an applied_spec_pack type activity", () => {
    const activity = createMockActivity({
      type: ActivityType.AppliedSpecPack,
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("edited a pack using fleetctl.")
    ).toBeInTheDocument();
  });

  it("renders an applied_spec_policy type activity", () => {
    const activity = createMockActivity({
      type: ActivityType.AppliedSpecPolicy,
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("edited policies using fleetctl.")
    ).toBeInTheDocument();
  });

  it("renders an applied_spec_saved_query type activity", () => {
    const activity = createMockActivity({
      type: ActivityType.AppliedSpecSavedQuery,
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("edited a query using fleetctl.")
    ).toBeInTheDocument();
  });

  it("renders an applied_spec_saved_query type activity when run on multiple queries", () => {
    const activity = createMockActivity({
      type: ActivityType.AppliedSpecSavedQuery,
      details: { specs: [createMockQuery(), createMockQuery()] },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("edited queries using fleetctl.")
    ).toBeInTheDocument();
  });

  it("renders an applied_spec_team type activity for a single team", () => {
    const activity = createMockActivity({
      type: ActivityType.AppliedSpecTeam,
      details: { teams: [createMockTeamSummary()] },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("edited the team using fleetctl.")
    ).toBeInTheDocument();
    expect(screen.getByText("Team 1")).toBeInTheDocument();
  });

  it("renders an applied_spec_team type activity for multiple team", () => {
    const activity = createMockActivity({
      type: ActivityType.AppliedSpecTeam,
      details: {
        teams: [createMockTeamSummary(), createMockTeamSummary()],
      },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("edited multiple teams using fleetctl.")
    ).toBeInTheDocument();
  });

  it("renders an user_added_by_sso type activity", () => {
    const activity = createMockActivity({
      type: ActivityType.UserAddedBySSO,
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(screen.getByText("was added to Fleet by SSO.")).toBeInTheDocument();
  });

  it("renders an edited_agent_options type activity for a team", () => {
    const activity = createMockActivity({
      type: ActivityType.EditedAgentOptions,
      details: { team_name: "Test Team 1" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("edited agent options on team.")
    ).toBeInTheDocument();
    expect(screen.getByText("Test Team 1")).toBeInTheDocument();
  });

  it("renders an edited_agent_options type activity globally", () => {
    const activity = createMockActivity({
      type: ActivityType.EditedAgentOptions,
      details: { global: true },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(screen.getByText("edited agent options.")).toBeInTheDocument();
  });

  it("renders a user_logged_in type activity globally", () => {
    const activity = createMockActivity({
      type: ActivityType.UserLoggedIn,
      details: { public_ip: "192.168.0.1" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("successfully logged in from public IP 192.168.0.1.")
    ).toBeInTheDocument();
  });

  it("renders a user_failed_login type activity globally", () => {
    const activity = createMockActivity({
      type: ActivityType.UserFailedLogin,
      details: { email: "foo@example.com", public_ip: "192.168.0.1" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText(" failed to log in from public IP 192.168.0.1.", {
        exact: false,
      })
    ).toBeInTheDocument();
    expect(
      screen.getByText("foo@example.com", { exact: false })
    ).toBeInTheDocument();
  });

  it("renders a created_user type activity globally", () => {
    const activity = createMockActivity({
      type: ActivityType.UserCreated,
      details: { user_email: "newuser@example.com" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("created a user", { exact: false })
    ).toBeInTheDocument();
    expect(screen.getByText("newuser@example.com")).toBeInTheDocument();
  });

  it("renders a deleted_user type activity globally", () => {
    const activity = createMockActivity({
      type: ActivityType.UserDeleted,
      details: { user_email: "newuser@example.com" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("deleted a user", { exact: false })
    ).toBeInTheDocument();
    expect(screen.getByText("newuser@example.com")).toBeInTheDocument();
  });

  it("renders a changed_user_global_role type activity globally for premium users", () => {
    const activity = createMockActivity({
      type: ActivityType.UserChangedGlobalRole,
      details: { user_email: "newuser@example.com", role: "maintainer" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(screen.getByText("changed", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("newuser@example.com")).toBeInTheDocument();
    expect(screen.getByText("maintainer")).toBeInTheDocument();
    expect(
      screen.getByText("for all teams.", { exact: false })
    ).toBeInTheDocument();
  });

  it("renders a changed_user_global_role type activity globally for free users", () => {
    const activity = createMockActivity({
      type: ActivityType.UserChangedGlobalRole,
      details: { user_email: "newuser@example.com", role: "maintainer" },
    });
    render(<ActivityItem activity={activity} isPremiumTier={false} />);

    expect(screen.getByText("changed", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("newuser@example.com")).toBeInTheDocument();
    expect(screen.getByText("maintainer")).toBeInTheDocument();
    const forAllTeams = screen.queryByText("for all teams.");
    expect(forAllTeams).toBeNull();
  });

  it("renders a changed_user_team_role type activity globally", () => {
    const activity = createMockActivity({
      type: ActivityType.UserChangedTeamRole,
      details: {
        user_email: "newuser@example.com",
        role: "maintainer",
        team_name: "Test Team",
      },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(screen.getByText("changed", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("newuser@example.com")).toBeInTheDocument();
    expect(screen.getByText("maintainer")).toBeInTheDocument();
    expect(screen.getByText("Test Team")).toBeInTheDocument();
  });

  it("renders a deleted_user_team_role type activity globally", () => {
    const activity = createMockActivity({
      type: ActivityType.UserDeletedTeamRole,
      details: {
        user_email: "newuser@example.com",
        team_name: "Test Team",
      },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(screen.getByText("removed", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("newuser@example.com")).toBeInTheDocument();
    expect(screen.getByText("Test Team")).toBeInTheDocument();
  });

  it("renders a deleted_user_global_role type activity globally for premium users", () => {
    const activity = createMockActivity({
      type: ActivityType.UserDeletedGlobalRole,
      details: { user_email: "newuser@example.com", role: "maintainer" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(screen.getByText("removed", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("newuser@example.com")).toBeInTheDocument();
    expect(screen.getByText("maintainer")).toBeInTheDocument();
    expect(
      screen.getByText("for all teams.", { exact: false })
    ).toBeInTheDocument();
  });

  it("renders a deleted_user_global_role type activity globally for free users", () => {
    const activity = createMockActivity({
      type: ActivityType.UserDeletedGlobalRole,
      details: { user_email: "newuser@example.com", role: "maintainer" },
    });
    render(<ActivityItem activity={activity} isPremiumTier={false} />);

    expect(screen.getByText("removed", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("newuser@example.com")).toBeInTheDocument();
    expect(screen.getByText("maintainer")).toBeInTheDocument();
    const forAllTeams = screen.queryByText("for all teams.");
    expect(forAllTeams).toBeNull();
  });

  it("renders an 'enabled_macos_disk_encryption' type activity for a team", () => {
    const activity = createMockActivity({
      type: ActivityType.EnabledMacDiskEncryption,
      details: { team_name: "Alphas" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText(
        "enforced disk encryption for macOS hosts assigned to the",
        {
          exact: false,
        }
      )
    ).toBeInTheDocument();
    expect(screen.getByText("Alphas")).toBeInTheDocument();
    expect(screen.getByText(" team.", { exact: false })).toBeInTheDocument();
    const withNoTeams = screen.queryByText("with no team");
    expect(withNoTeams).toBeNull();
  });

  it("renders a 'disabled_macos_disk_encryption' type activity for a team", () => {
    const activity = createMockActivity({
      type: ActivityType.DisabledMacDiskEncryption,
      details: { team_name: "Alphas" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText(
        "removed disk encryption enforcement for macOS hosts assigned to the",
        {
          exact: false,
        }
      )
    ).toBeInTheDocument();
    expect(screen.getByText("Alphas")).toBeInTheDocument();
    expect(screen.getByText(" team.", { exact: false })).toBeInTheDocument();
    const withNoTeams = screen.queryByText("with no team");
    expect(withNoTeams).toBeNull();
  });

  it("renders an 'enabled_macos_disk_encryption' type activity for hosts with no team.", () => {
    const activity = createMockActivity({
      type: ActivityType.EnabledMacDiskEncryption,
      details: {},
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("enforced disk encryption for macOS hosts with no team.")
    ).toBeInTheDocument();
    expect(screen.queryByText("assigned to the")).toBeNull();
  });

  it("renders a 'disabled_macos_disk_encryption' type activity for hosts with no team.", () => {
    const activity = createMockActivity({
      type: ActivityType.DisabledMacDiskEncryption,
      details: {},
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText(
        "removed disk encryption enforcement for macOS hosts with no team.",
        {
          exact: false,
        }
      )
    ).toBeInTheDocument();
    expect(screen.queryByText("assigned to the")).toBeNull();
  });

  it("renders a 'changed_macos_setup_assistant' type activity for no team", () => {
    const activity = createMockActivity({
      type: ActivityType.ChangedMacOSSetupAssistant,
      details: { name: "dep-profile.json" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText((content, node) => {
        return (
          node?.innerHTML ===
          "<b>Test User </b> changed the macOS Setup Assistant (added <b>dep-profile.json</b>) for hosts that automatically enroll to no team."
        );
      })
    ).toBeInTheDocument();
  });

  it("renders a 'changed_macos_setup_assistant' type activity for a team", () => {
    const activity = createMockActivity({
      type: ActivityType.ChangedMacOSSetupAssistant,
      details: { name: "dep-profile.json", team_name: "Workstations" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText((content, node) => {
        return (
          node?.innerHTML ===
          "<b>Test User </b> changed the macOS Setup Assistant (added <b>dep-profile.json</b>) for hosts  that automatically enroll to the <b>Workstations</b> team."
        );
      })
    ).toBeInTheDocument();
  });

  it("renders a 'deleted_macos_setup_assistant' type activity for no team", () => {
    const activity = createMockActivity({
      type: ActivityType.DeletedMacOSSetupAssistant,
      details: { name: "dep-profile.json" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText((content, node) => {
        return (
          node?.innerHTML ===
          "<b>Test User </b> changed the macOS Setup Assistant (deleted <b>dep-profile.json</b>) for hosts that automatically enroll to no team."
        );
      })
    ).toBeInTheDocument();
  });

  it("renders a 'deleted_macos_setup_assistant' type activity for a team", () => {
    const activity = createMockActivity({
      type: ActivityType.DeletedMacOSSetupAssistant,
      details: { name: "dep-profile.json", team_name: "Workstations" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText((content, node) => {
        return (
          node?.innerHTML ===
          "<b>Test User </b> changed the macOS Setup Assistant (deleted <b>dep-profile.json</b>) for hosts  that automatically enroll to the <b>Workstations</b> team."
        );
      })
    ).toBeInTheDocument();
  });

  it("renders a 'added_bootstrap_package' type activity for a team", () => {
    const activity = createMockActivity({
      type: ActivityType.AddedBootstrapPackage,
      details: { bootstrap_package_name: "foo.pkg", team_name: "Alphas" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("added a bootstrap package (", { exact: false })
    ).toBeInTheDocument();
    expect(screen.getByText("foo.pkg", { exact: false })).toBeInTheDocument();
    expect(
      screen.getByText(") for macOS hosts that automatically enroll to the ", {
        exact: false,
      })
    ).toBeInTheDocument();
    expect(screen.getByText("Alphas")).toBeInTheDocument();
    expect(screen.getByText(" team.", { exact: false })).toBeInTheDocument();
    const withNoTeams = screen.queryByText("automatically enroll to no team");
    expect(withNoTeams).toBeNull();
  });

  it("renders a 'deleted_bootstrap_package' type activity for a team", () => {
    const activity = createMockActivity({
      type: ActivityType.DeletedBootstrapPackage,
      details: { bootstrap_package_name: "foo.pkg", team_name: "Alphas" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("deleted a bootstrap package (", { exact: false })
    ).toBeInTheDocument();
    expect(screen.getByText("foo.pkg", { exact: false })).toBeInTheDocument();
    expect(
      screen.getByText(") for macOS hosts that automatically enroll to the ", {
        exact: false,
      })
    ).toBeInTheDocument();
    expect(screen.getByText("Alphas")).toBeInTheDocument();
    expect(screen.getByText(" team.", { exact: false })).toBeInTheDocument();
    const withNoTeams = screen.queryByText("automatically enroll to no team");
    expect(withNoTeams).toBeNull();
  });

  it("renders a 'added_bootstrap_package' type activity for hosts with no team.", () => {
    const activity = createMockActivity({
      type: ActivityType.AddedBootstrapPackage,
      details: { bootstrap_package_name: "foo.pkg" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("added a bootstrap package (", { exact: false })
    ).toBeInTheDocument();
    expect(screen.getByText("foo.pkg", { exact: false })).toBeInTheDocument();
    expect(
      screen.getByText(
        ") for macOS hosts that automatically enroll to no team.",
        { exact: false }
      )
    ).toBeInTheDocument();
  });

  it("renders a 'deleted_bootstrap_package' type activity for hosts with no team.", () => {
    const activity = createMockActivity({
      type: ActivityType.DeletedBootstrapPackage,
      details: { bootstrap_package_name: "foo.pkg" },
    });
    render(<ActivityItem activity={activity} isPremiumTier />);

    expect(
      screen.getByText("deleted a bootstrap package (", { exact: false })
    ).toBeInTheDocument();
    expect(screen.getByText("foo.pkg", { exact: false })).toBeInTheDocument();
    expect(
      screen.getByText(
        ") for macOS hosts that automatically enroll to no team.",
        { exact: false }
      )
    ).toBeInTheDocument();
  });
});
