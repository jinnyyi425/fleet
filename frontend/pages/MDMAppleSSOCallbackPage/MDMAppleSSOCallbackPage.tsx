import React, { useState } from "react";
import { WithRouterProps } from "react-router";

import endpoints from "utilities/endpoints";

import Spinner from "components/Spinner/Spinner";
import SSOError from "components/MDM/SSOError";
import Button from "components/buttons/Button";

const baseClass = "mdm-apple-sso-callback-page";

const RedirectTo = ({ url }: { url: string }) => {
  window.location.href = url;
  return <Spinner />;
};

interface IEnrollmentGateProps {
  profileToken?: string;
  eulaToken?: string;
}

const EnrollmentGate = ({ profileToken, eulaToken }: IEnrollmentGateProps) => {
  const [showEULA, setShowEULA] = useState(Boolean(eulaToken));

  if (!profileToken) {
    return <SSOError />;
  }

  if (showEULA && eulaToken) {
    return (
      <div className={`${baseClass}__eula-wrapper`}>
        <h3>Terms and conditions</h3>
        <iframe
          src={`/api/${endpoints.MDM_APPLE_EULA_FILE(eulaToken)}`}
          width="100%"
          title="eula"
        />
        <Button
          onClick={() => setShowEULA(false)}
          variant="oversized"
          className={`${baseClass}__agree-btn`}
        >
          Agree and continue
        </Button>
      </div>
    );
  }

  return (
    <RedirectTo url={endpoints.MDM_APPLE_ENROLLMENT_PROFILE(profileToken)} />
  );
};

interface IMDMSSOCallbackQuery {
  eula_token?: string;
  profile_token?: string;
}

const MDMAppleSSOCallbackPage = (
  props: WithRouterProps<object, IMDMSSOCallbackQuery>
) => {
  const { eula_token, profile_token } = props.location.query;
  return (
    <div className={baseClass}>
      <EnrollmentGate eulaToken={eula_token} profileToken={profile_token} />
    </div>
  );
};

export default MDMAppleSSOCallbackPage;
