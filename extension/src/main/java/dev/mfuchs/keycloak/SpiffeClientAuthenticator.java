package dev.mfuchs.keycloak;

import jakarta.ws.rs.core.MediaType;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.authentication.authenticators.client.X509ClientAuthenticator;
import org.keycloak.authentication.authenticators.x509.CertificateValidator;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Lab-only extension: authenticate a Keycloak client by an exact SPIFFE URI SAN. Keycloak's direct TLS certificate lookup must be used; proxy certificate headers
 * must not be configured. TLS requires a client certificate and trusts only SPIRE.
 */
public final class SpiffeClientAuthenticator extends X509ClientAuthenticator {

    public static final String ID = "spiffe-x509";

    public static final String CLIENT_ATTRIBUTE = "spiffe.id";

    static String spiffeId(final X509Certificate cert) throws GeneralSecurityException {
        final var sans = cert.getSubjectAlternativeNames();
        if (sans == null) {
            return null;
        }

        String found = null;
        for (Object entry : sans) {
            if (!(entry instanceof java.util.List<?> san) || san.size() < 2)
                continue;
            if (!Integer.valueOf(6).equals(san.get(0)))
                continue;
            if (!(san.get(1) instanceof String value))
                return null;

            URI uri;
            try {
                uri = URI.create(value);
            } catch (IllegalArgumentException e) {
                return null;
            }

            if (!"spiffe".equals(uri.getScheme()) || uri.getHost() == null ||
                    uri.getUserInfo() != null || uri.getPort() != -1 ||
                    uri.getQuery() != null || uri.getFragment() != null ||
                    uri.getPath() == null || uri.getPath().isBlank() || found != null
            )
                return null;

            found = uri.toString();
        }
        return found;
    }

    private static void reject(final ClientAuthenticationFlowContext context) {
        final var response = ClientAuthUtil.errorResponse(401, "invalid_client", "Client certificate rejected");
        context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, response);
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "SPIFFE X.509 client";
    }

    @Override
    public String getHelpText() {
        return "Exact SPIFFE URI SAN to Keycloak client mapping";
    }

    @Override
    public void authenticateClient(final ClientAuthenticationFlowContext context) {
        try {
            final var lookup = context.getSession().getProvider(X509ClientCertificateLookup.class);
            if (lookup == null) {
                reject(context);
                return;
            }

            final var chain = lookup.getCertificateChain(context.getHttpRequest());
            if (chain == null || chain.length == 0) {
                reject(context);
                return;
            }

            final var type = context.getHttpRequest().getHttpHeaders().getMediaType();
            if (type == null || !type.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE)) {
                reject(context);
                return;
            }

            final var clientId = context.getHttpRequest().getDecodedFormParameters().getFirst(OAuth2Constants.CLIENT_ID);
            if (clientId == null || clientId.isBlank()) {
                reject(context);
                return;
            }

            final var client = context.getRealm().getClientByClientId(clientId);
            if (client == null || !client.isEnabled() || !ID.equals(client.getClientAuthenticatorType())) {
                reject(context);
                return;
            }

            // This checks the SPIRE trust anchor and certificate validity in addition to the TLS handshake. Never trust the SAN from an unvalidated chain.
            final var validator = new CertificateValidator.CertificateValidatorBuilder()
                    .session(context.getSession())
                    .trustValidation().enabled(true)
                    .timestampValidation().enabled(true)
                    .build(chain);
            validator.validateTimestamps().validateTrust();

            final String actual = spiffeId(chain[0]);
            final String expected = client.getAttribute(CLIENT_ATTRIBUTE);
            if (actual == null || expected == null || !Objects.equals(actual, expected)) {
                reject(context);
                return;
            }

            context.getEvent().client(clientId);
            context.setClient(client);
            context.success();
        } catch (GeneralSecurityException | RuntimeException e) {
            logger.warn("SPIFFE client authentication failed", e);
            reject(context);
        }
    }
}
