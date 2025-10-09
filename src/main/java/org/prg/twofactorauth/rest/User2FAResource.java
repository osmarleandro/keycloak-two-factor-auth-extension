package org.prg.twofactorauth.rest;

import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.Base32;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.MediaType;
import org.keycloak.utils.TotpUtils;
import org.prg.twofactorauth.dto.TwoFactorAuthSecretData;
import org.prg.twofactorauth.dto.TwoFactorAuthSubmission;
import org.prg.twofactorauth.dto.TwoFactorAuthVerificationData;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.CacheControl;
import jakarta.ws.rs.core.Response;

public class User2FAResource {

    private final KeycloakSession session;
    private final UserModel user;

    public final int TotpSecretLength = 20;

    public User2FAResource(KeycloakSession session, UserModel user) {
        this.session = session;
        this.user = user;
    }

    @GET
    @Path("generate-2fa")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response generate2FA() {
        CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);
        cacheControl.setNoStore(true);

        final RealmModel realm = this.session.getContext().getRealm();
        final String totpSecret = HmacOTP.generateSecret(TotpSecretLength);
        final String totpSecretQrCode = TotpUtils.qrCode(totpSecret, realm, user);
        final String totpSecretEncoded = Base32.encode(totpSecret.getBytes());
        return Response.ok(new TwoFactorAuthSecretData(totpSecretEncoded, totpSecretQrCode)).build();
    }

    @POST
    @Path("validate-2fa-code")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validate2FACode(final TwoFactorAuthVerificationData submission) {
        CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);
        cacheControl.setNoStore(true);

        if (!submission.isValid()) {
            throw new BadRequestException("one or more data field for otp validation are blank");
        }
        String submissionTotpCode = submission.getTotpCode();

        try {
            boolean isPasswordValid = user.credentialManager()
                    .isValid(UserCredentialModel.password(submission.getPassword()));

            if (!isPasswordValid) {
                return createErrorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant",
                        "Invalid user credential: password");
            }


            final CredentialModel credentialModel = user.credentialManager()
                    .getStoredCredentialByNameAndType(submission.getDeviceName(), OTPCredentialModel.TYPE);

            if (credentialModel == null) {
                return createErrorResponse(Response.Status.NOT_FOUND.getStatusCode(), "device not found",
                        "device not found");
            }

            final OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromCredentialModel(credentialModel);
            final String credentialId = otpCredentialModel.getId();

            boolean isCredentialsValid = user.credentialManager().isValid(
                    new UserCredentialModel(credentialId, otpCredentialModel.getType(), submissionTotpCode));

            if (!isCredentialsValid) {
                return createErrorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant",
                        "Invalid user credential: otp");
            }


        } catch (RuntimeException e) {
            throw new InternalServerErrorException("internal error");
        }

        return Response.noContent().build();
    }

    private Response createErrorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    @POST
    @Path("submit-2fa")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register2FA(final TwoFactorAuthSubmission submission) {
        CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);
        cacheControl.setNoStore(true);

        if (!submission.isValid()) {
            throw new BadRequestException("one or more data field for otp registration are blank");
        }

        final String encodedTotpSecret = submission.getEncodedTotpSecret();
        final String totpSecret = new String(Base32.decode(encodedTotpSecret));
        if (totpSecret.length() < TotpSecretLength) {
            throw new BadRequestException("totp secret is invalid");
        }

        final RealmModel realm = this.session.getContext().getRealm();
        final CredentialModel credentialModel =
                user.credentialManager().getStoredCredentialByNameAndType(submission.getDeviceName(), OTPCredentialModel.TYPE);

        if (credentialModel != null && !submission.isOverwrite()) {
            throw new ForbiddenException("2FA is already configured for device: " + submission.getDeviceName());
        }

        final OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromPolicy(realm, totpSecret,
                submission.getDeviceName());

        if (!CredentialHelper.createOTPCredential(this.session, realm, user, submission.getTotpInitialCode(),
                otpCredentialModel)) {
            throw new BadRequestException("otp registration data is invalid");
        }

        return Response.noContent().build();
    }

}