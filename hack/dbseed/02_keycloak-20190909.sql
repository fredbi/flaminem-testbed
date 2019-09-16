--
-- PostgreSQL database cluster dump
--

SET default_transaction_read_only = off;

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

--
-- Drop databases
--

DROP DATABASE customer;
DROP DATABASE dbuser;
DROP DATABASE flaminem;
DROP DATABASE oidc;




--
-- Drop roles
--

DROP ROLE dbuser;
DROP ROLE postgres;


--
-- Roles
--

CREATE ROLE dbuser;
ALTER ROLE dbuser WITH SUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'md528bd1c9260e10bf54ae1622797b07587';
CREATE ROLE postgres;
ALTER ROLE postgres WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS;






--
-- Database creation
--

CREATE DATABASE customer WITH TEMPLATE = template0 OWNER = dbuser;
CREATE DATABASE dbuser WITH TEMPLATE = template0 OWNER = postgres;
CREATE DATABASE flaminem WITH TEMPLATE = template0 OWNER = dbuser;
CREATE DATABASE oidc WITH TEMPLATE = template0 OWNER = dbuser;
REVOKE CONNECT,TEMPORARY ON DATABASE template1 FROM PUBLIC;
GRANT CONNECT ON DATABASE template1 TO PUBLIC;


\connect customer

SET default_transaction_read_only = off;

--
-- PostgreSQL database dump
--

-- Dumped from database version 10.4
-- Dumped by pg_dump version 10.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: admin_event_entity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.admin_event_entity (
    id character varying(36) NOT NULL,
    admin_event_time bigint,
    realm_id character varying(255),
    operation_type character varying(255),
    auth_realm_id character varying(255),
    auth_client_id character varying(255),
    auth_user_id character varying(255),
    ip_address character varying(255),
    resource_path character varying(2550),
    representation text,
    error character varying(255),
    resource_type character varying(64)
);


ALTER TABLE public.admin_event_entity OWNER TO dbuser;

--
-- Name: associated_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.associated_policy (
    policy_id character varying(36) NOT NULL,
    associated_policy_id character varying(36) NOT NULL
);


ALTER TABLE public.associated_policy OWNER TO dbuser;

--
-- Name: authentication_execution; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authentication_execution (
    id character varying(36) NOT NULL,
    alias character varying(255),
    authenticator character varying(36),
    realm_id character varying(36),
    flow_id character varying(36),
    requirement integer,
    priority integer,
    authenticator_flow boolean DEFAULT false NOT NULL,
    auth_flow_id character varying(36),
    auth_config character varying(36)
);


ALTER TABLE public.authentication_execution OWNER TO dbuser;

--
-- Name: authentication_flow; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authentication_flow (
    id character varying(36) NOT NULL,
    alias character varying(255),
    description character varying(255),
    realm_id character varying(36),
    provider_id character varying(36) DEFAULT 'basic-flow'::character varying NOT NULL,
    top_level boolean DEFAULT false NOT NULL,
    built_in boolean DEFAULT false NOT NULL
);


ALTER TABLE public.authentication_flow OWNER TO dbuser;

--
-- Name: authenticator_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authenticator_config (
    id character varying(36) NOT NULL,
    alias character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.authenticator_config OWNER TO dbuser;

--
-- Name: authenticator_config_entry; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authenticator_config_entry (
    authenticator_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.authenticator_config_entry OWNER TO dbuser;

--
-- Name: broker_link; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.broker_link (
    identity_provider character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL,
    broker_user_id character varying(255),
    broker_username character varying(255),
    token text,
    user_id character varying(255) NOT NULL
);


ALTER TABLE public.broker_link OWNER TO dbuser;

--
-- Name: client; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client (
    id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    full_scope_allowed boolean DEFAULT false NOT NULL,
    client_id character varying(255),
    not_before integer,
    public_client boolean DEFAULT false NOT NULL,
    secret character varying(255),
    base_url character varying(255),
    bearer_only boolean DEFAULT false NOT NULL,
    management_url character varying(255),
    surrogate_auth_required boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    protocol character varying(255),
    node_rereg_timeout integer DEFAULT 0,
    frontchannel_logout boolean DEFAULT false NOT NULL,
    consent_required boolean DEFAULT false NOT NULL,
    name character varying(255),
    service_accounts_enabled boolean DEFAULT false NOT NULL,
    client_authenticator_type character varying(255),
    root_url character varying(255),
    description character varying(255),
    registration_token character varying(255),
    standard_flow_enabled boolean DEFAULT true NOT NULL,
    implicit_flow_enabled boolean DEFAULT false NOT NULL,
    direct_access_grants_enabled boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client OWNER TO dbuser;

--
-- Name: client_attributes; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_attributes (
    client_id character varying(36) NOT NULL,
    value character varying(4000),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_attributes OWNER TO dbuser;

--
-- Name: client_auth_flow_bindings; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_auth_flow_bindings (
    client_id character varying(36) NOT NULL,
    flow_id character varying(36),
    binding_name character varying(255) NOT NULL
);


ALTER TABLE public.client_auth_flow_bindings OWNER TO dbuser;

--
-- Name: client_default_roles; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_default_roles (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_default_roles OWNER TO dbuser;

--
-- Name: client_initial_access; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_initial_access (
    id character varying(36) NOT NULL,
    realm_id character varying(36) NOT NULL,
    "timestamp" integer,
    expiration integer,
    count integer,
    remaining_count integer
);


ALTER TABLE public.client_initial_access OWNER TO dbuser;

--
-- Name: client_node_registrations; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_node_registrations (
    client_id character varying(36) NOT NULL,
    value integer,
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_node_registrations OWNER TO dbuser;

--
-- Name: client_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope (
    id character varying(36) NOT NULL,
    name character varying(255),
    realm_id character varying(36),
    description character varying(255),
    protocol character varying(255)
);


ALTER TABLE public.client_scope OWNER TO dbuser;

--
-- Name: client_scope_attributes; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope_attributes (
    scope_id character varying(36) NOT NULL,
    value character varying(2048),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_scope_attributes OWNER TO dbuser;

--
-- Name: client_scope_client; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope_client (
    client_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client_scope_client OWNER TO dbuser;

--
-- Name: client_scope_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope_role_mapping (
    scope_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_scope_role_mapping OWNER TO dbuser;

--
-- Name: client_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    redirect_uri character varying(255),
    state character varying(255),
    "timestamp" integer,
    session_id character varying(36),
    auth_method character varying(255),
    realm_id character varying(255),
    auth_user_id character varying(36),
    current_action character varying(36)
);


ALTER TABLE public.client_session OWNER TO dbuser;

--
-- Name: client_session_auth_status; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_auth_status (
    authenticator character varying(36) NOT NULL,
    status integer,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_auth_status OWNER TO dbuser;

--
-- Name: client_session_note; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_note (
    name character varying(255) NOT NULL,
    value character varying(255),
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_note OWNER TO dbuser;

--
-- Name: client_session_prot_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_prot_mapper (
    protocol_mapper_id character varying(36) NOT NULL,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_prot_mapper OWNER TO dbuser;

--
-- Name: client_session_role; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_role (
    role_id character varying(255) NOT NULL,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_role OWNER TO dbuser;

--
-- Name: client_user_session_note; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_user_session_note (
    name character varying(255) NOT NULL,
    value character varying(2048),
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_user_session_note OWNER TO dbuser;

--
-- Name: component; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.component (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_id character varying(36),
    provider_id character varying(36),
    provider_type character varying(255),
    realm_id character varying(36),
    sub_type character varying(255)
);


ALTER TABLE public.component OWNER TO dbuser;

--
-- Name: component_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.component_config (
    id character varying(36) NOT NULL,
    component_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.component_config OWNER TO dbuser;

--
-- Name: composite_role; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.composite_role (
    composite character varying(36) NOT NULL,
    child_role character varying(36) NOT NULL
);


ALTER TABLE public.composite_role OWNER TO dbuser;

--
-- Name: credential; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.credential (
    id character varying(36) NOT NULL,
    device character varying(255),
    hash_iterations integer,
    salt bytea,
    type character varying(255),
    value character varying(4000),
    user_id character varying(36),
    created_date bigint,
    counter integer DEFAULT 0,
    digits integer DEFAULT 6,
    period integer DEFAULT 30,
    algorithm character varying(36) DEFAULT NULL::character varying
);


ALTER TABLE public.credential OWNER TO dbuser;

--
-- Name: credential_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.credential_attribute (
    id character varying(36) NOT NULL,
    credential_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.credential_attribute OWNER TO dbuser;

--
-- Name: databasechangelog; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.databasechangelog (
    id character varying(255) NOT NULL,
    author character varying(255) NOT NULL,
    filename character varying(255) NOT NULL,
    dateexecuted timestamp without time zone NOT NULL,
    orderexecuted integer NOT NULL,
    exectype character varying(10) NOT NULL,
    md5sum character varying(35),
    description character varying(255),
    comments character varying(255),
    tag character varying(255),
    liquibase character varying(20),
    contexts character varying(255),
    labels character varying(255),
    deployment_id character varying(10)
);


ALTER TABLE public.databasechangelog OWNER TO dbuser;

--
-- Name: databasechangeloglock; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.databasechangeloglock (
    id integer NOT NULL,
    locked boolean NOT NULL,
    lockgranted timestamp without time zone,
    lockedby character varying(255)
);


ALTER TABLE public.databasechangeloglock OWNER TO dbuser;

--
-- Name: default_client_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.default_client_scope (
    realm_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.default_client_scope OWNER TO dbuser;

--
-- Name: event_entity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.event_entity (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    details_json character varying(2550),
    error character varying(255),
    ip_address character varying(255),
    realm_id character varying(255),
    session_id character varying(255),
    event_time bigint,
    type character varying(255),
    user_id character varying(255)
);


ALTER TABLE public.event_entity OWNER TO dbuser;

--
-- Name: fed_credential_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_credential_attribute (
    id character varying(36) NOT NULL,
    credential_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.fed_credential_attribute OWNER TO dbuser;

--
-- Name: fed_user_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_attribute (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    value character varying(2024)
);


ALTER TABLE public.fed_user_attribute OWNER TO dbuser;

--
-- Name: fed_user_consent; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.fed_user_consent OWNER TO dbuser;

--
-- Name: fed_user_consent_cl_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_consent_cl_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.fed_user_consent_cl_scope OWNER TO dbuser;

--
-- Name: fed_user_credential; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_credential (
    id character varying(36) NOT NULL,
    device character varying(255),
    hash_iterations integer,
    salt bytea,
    type character varying(255),
    value character varying(255),
    created_date bigint,
    counter integer DEFAULT 0,
    digits integer DEFAULT 6,
    period integer DEFAULT 30,
    algorithm character varying(36) DEFAULT 'HmacSHA1'::character varying,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_credential OWNER TO dbuser;

--
-- Name: fed_user_group_membership; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_group_membership OWNER TO dbuser;

--
-- Name: fed_user_required_action; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_required_action (
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_required_action OWNER TO dbuser;

--
-- Name: fed_user_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_role_mapping (
    role_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_role_mapping OWNER TO dbuser;

--
-- Name: federated_identity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.federated_identity (
    identity_provider character varying(255) NOT NULL,
    realm_id character varying(36),
    federated_user_id character varying(255),
    federated_username character varying(255),
    token text,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_identity OWNER TO dbuser;

--
-- Name: federated_user; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.federated_user (
    id character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_user OWNER TO dbuser;

--
-- Name: group_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.group_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_attribute OWNER TO dbuser;

--
-- Name: group_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.group_role_mapping (
    role_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_role_mapping OWNER TO dbuser;

--
-- Name: identity_provider; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.identity_provider (
    internal_id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    provider_alias character varying(255),
    provider_id character varying(255),
    store_token boolean DEFAULT false NOT NULL,
    authenticate_by_default boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    add_token_role boolean DEFAULT true NOT NULL,
    trust_email boolean DEFAULT false NOT NULL,
    first_broker_login_flow_id character varying(36),
    post_broker_login_flow_id character varying(36),
    provider_display_name character varying(255),
    link_only boolean DEFAULT false NOT NULL
);


ALTER TABLE public.identity_provider OWNER TO dbuser;

--
-- Name: identity_provider_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.identity_provider_config (
    identity_provider_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.identity_provider_config OWNER TO dbuser;

--
-- Name: identity_provider_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.identity_provider_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    idp_alias character varying(255) NOT NULL,
    idp_mapper_name character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.identity_provider_mapper OWNER TO dbuser;

--
-- Name: idp_mapper_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.idp_mapper_config (
    idp_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.idp_mapper_config OWNER TO dbuser;

--
-- Name: keycloak_group; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.keycloak_group (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_group character varying(36),
    realm_id character varying(36)
);


ALTER TABLE public.keycloak_group OWNER TO dbuser;

--
-- Name: keycloak_role; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.keycloak_role (
    id character varying(36) NOT NULL,
    client_realm_constraint character varying(36),
    client_role boolean DEFAULT false NOT NULL,
    description character varying(255),
    name character varying(255),
    realm_id character varying(255),
    client character varying(36),
    realm character varying(36)
);


ALTER TABLE public.keycloak_role OWNER TO dbuser;

--
-- Name: migration_model; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.migration_model (
    id character varying(36) NOT NULL,
    version character varying(36)
);


ALTER TABLE public.migration_model OWNER TO dbuser;

--
-- Name: offline_client_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.offline_client_session (
    user_session_id character varying(36) NOT NULL,
    client_id character varying(36) NOT NULL,
    offline_flag character varying(4) NOT NULL,
    "timestamp" integer,
    data text,
    client_storage_provider character varying(36) DEFAULT 'local'::character varying NOT NULL,
    external_client_id character varying(255) DEFAULT 'local'::character varying NOT NULL
);


ALTER TABLE public.offline_client_session OWNER TO dbuser;

--
-- Name: offline_user_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.offline_user_session (
    user_session_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    created_on integer NOT NULL,
    offline_flag character varying(4) NOT NULL,
    data text,
    last_session_refresh integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.offline_user_session OWNER TO dbuser;

--
-- Name: policy_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.policy_config (
    policy_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.policy_config OWNER TO dbuser;

--
-- Name: protocol_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.protocol_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    protocol character varying(255) NOT NULL,
    protocol_mapper_name character varying(255) NOT NULL,
    client_id character varying(36),
    client_scope_id character varying(36)
);


ALTER TABLE public.protocol_mapper OWNER TO dbuser;

--
-- Name: protocol_mapper_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.protocol_mapper_config (
    protocol_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.protocol_mapper_config OWNER TO dbuser;

--
-- Name: realm; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm (
    id character varying(36) NOT NULL,
    access_code_lifespan integer,
    user_action_lifespan integer,
    access_token_lifespan integer,
    account_theme character varying(255),
    admin_theme character varying(255),
    email_theme character varying(255),
    enabled boolean DEFAULT false NOT NULL,
    events_enabled boolean DEFAULT false NOT NULL,
    events_expiration bigint,
    login_theme character varying(255),
    name character varying(255),
    not_before integer,
    password_policy character varying(2550),
    registration_allowed boolean DEFAULT false NOT NULL,
    remember_me boolean DEFAULT false NOT NULL,
    reset_password_allowed boolean DEFAULT false NOT NULL,
    social boolean DEFAULT false NOT NULL,
    ssl_required character varying(255),
    sso_idle_timeout integer,
    sso_max_lifespan integer,
    update_profile_on_soc_login boolean DEFAULT false NOT NULL,
    verify_email boolean DEFAULT false NOT NULL,
    master_admin_client character varying(36),
    login_lifespan integer,
    internationalization_enabled boolean DEFAULT false NOT NULL,
    default_locale character varying(255),
    reg_email_as_username boolean DEFAULT false NOT NULL,
    admin_events_enabled boolean DEFAULT false NOT NULL,
    admin_events_details_enabled boolean DEFAULT false NOT NULL,
    edit_username_allowed boolean DEFAULT false NOT NULL,
    otp_policy_counter integer DEFAULT 0,
    otp_policy_window integer DEFAULT 1,
    otp_policy_period integer DEFAULT 30,
    otp_policy_digits integer DEFAULT 6,
    otp_policy_alg character varying(36) DEFAULT 'HmacSHA1'::character varying,
    otp_policy_type character varying(36) DEFAULT 'totp'::character varying,
    browser_flow character varying(36),
    registration_flow character varying(36),
    direct_grant_flow character varying(36),
    reset_credentials_flow character varying(36),
    client_auth_flow character varying(36),
    offline_session_idle_timeout integer DEFAULT 0,
    revoke_refresh_token boolean DEFAULT false NOT NULL,
    access_token_life_implicit integer DEFAULT 0,
    login_with_email_allowed boolean DEFAULT true NOT NULL,
    duplicate_emails_allowed boolean DEFAULT false NOT NULL,
    docker_auth_flow character varying(36),
    refresh_token_max_reuse integer DEFAULT 0,
    allow_user_managed_access boolean DEFAULT false NOT NULL,
    sso_max_lifespan_remember_me integer DEFAULT 0 NOT NULL,
    sso_idle_timeout_remember_me integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.realm OWNER TO dbuser;

--
-- Name: realm_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_attribute OWNER TO dbuser;

--
-- Name: realm_default_groups; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_default_groups (
    realm_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_groups OWNER TO dbuser;

--
-- Name: realm_default_roles; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_default_roles (
    realm_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_roles OWNER TO dbuser;

--
-- Name: realm_enabled_event_types; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_enabled_event_types (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_enabled_event_types OWNER TO dbuser;

--
-- Name: realm_events_listeners; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_events_listeners (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_events_listeners OWNER TO dbuser;

--
-- Name: realm_required_credential; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_required_credential (
    type character varying(255) NOT NULL,
    form_label character varying(255),
    input boolean DEFAULT false NOT NULL,
    secret boolean DEFAULT false NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_required_credential OWNER TO dbuser;

--
-- Name: realm_smtp_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_smtp_config (
    realm_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.realm_smtp_config OWNER TO dbuser;

--
-- Name: realm_supported_locales; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_supported_locales (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_supported_locales OWNER TO dbuser;

--
-- Name: redirect_uris; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.redirect_uris (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.redirect_uris OWNER TO dbuser;

--
-- Name: required_action_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.required_action_config (
    required_action_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.required_action_config OWNER TO dbuser;

--
-- Name: required_action_provider; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.required_action_provider (
    id character varying(36) NOT NULL,
    alias character varying(255),
    name character varying(255),
    realm_id character varying(36),
    enabled boolean DEFAULT false NOT NULL,
    default_action boolean DEFAULT false NOT NULL,
    provider_id character varying(255),
    priority integer
);


ALTER TABLE public.required_action_provider OWNER TO dbuser;

--
-- Name: resource_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    resource_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_attribute OWNER TO dbuser;

--
-- Name: resource_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_policy (
    resource_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_policy OWNER TO dbuser;

--
-- Name: resource_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_scope (
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_scope OWNER TO dbuser;

--
-- Name: resource_server; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server (
    id character varying(36) NOT NULL,
    allow_rs_remote_mgmt boolean DEFAULT false NOT NULL,
    policy_enforce_mode character varying(15) NOT NULL
);


ALTER TABLE public.resource_server OWNER TO dbuser;

--
-- Name: resource_server_perm_ticket; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_perm_ticket (
    id character varying(36) NOT NULL,
    owner character varying(36) NOT NULL,
    requester character varying(36) NOT NULL,
    created_timestamp bigint NOT NULL,
    granted_timestamp bigint,
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36),
    resource_server_id character varying(36) NOT NULL,
    policy_id character varying(36)
);


ALTER TABLE public.resource_server_perm_ticket OWNER TO dbuser;

--
-- Name: resource_server_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_policy (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255),
    type character varying(255) NOT NULL,
    decision_strategy character varying(20),
    logic character varying(20),
    resource_server_id character varying(36) NOT NULL,
    owner character varying(36)
);


ALTER TABLE public.resource_server_policy OWNER TO dbuser;

--
-- Name: resource_server_resource; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_resource (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    type character varying(255),
    icon_uri character varying(255),
    owner character varying(36) NOT NULL,
    resource_server_id character varying(36) NOT NULL,
    owner_managed_access boolean DEFAULT false NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_resource OWNER TO dbuser;

--
-- Name: resource_server_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_scope (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    icon_uri character varying(255),
    resource_server_id character varying(36) NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_scope OWNER TO dbuser;

--
-- Name: resource_uris; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_uris (
    resource_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.resource_uris OWNER TO dbuser;

--
-- Name: role_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.role_attribute (
    id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255)
);


ALTER TABLE public.role_attribute OWNER TO dbuser;

--
-- Name: scope_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.scope_mapping (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_mapping OWNER TO dbuser;

--
-- Name: scope_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.scope_policy (
    scope_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_policy OWNER TO dbuser;

--
-- Name: user_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    user_id character varying(36) NOT NULL,
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL
);


ALTER TABLE public.user_attribute OWNER TO dbuser;

--
-- Name: user_consent; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    user_id character varying(36) NOT NULL,
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.user_consent OWNER TO dbuser;

--
-- Name: user_consent_client_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_consent_client_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.user_consent_client_scope OWNER TO dbuser;

--
-- Name: user_entity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_entity (
    id character varying(36) NOT NULL,
    email character varying(255),
    email_constraint character varying(255),
    email_verified boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    federation_link character varying(255),
    first_name character varying(255),
    last_name character varying(255),
    realm_id character varying(255),
    username character varying(255),
    created_timestamp bigint,
    service_account_client_link character varying(36),
    not_before integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.user_entity OWNER TO dbuser;

--
-- Name: user_federation_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_config (
    user_federation_provider_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_config OWNER TO dbuser;

--
-- Name: user_federation_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    federation_provider_id character varying(36) NOT NULL,
    federation_mapper_type character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.user_federation_mapper OWNER TO dbuser;

--
-- Name: user_federation_mapper_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_mapper_config (
    user_federation_mapper_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_mapper_config OWNER TO dbuser;

--
-- Name: user_federation_provider; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_provider (
    id character varying(36) NOT NULL,
    changed_sync_period integer,
    display_name character varying(255),
    full_sync_period integer,
    last_sync integer,
    priority integer,
    provider_name character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.user_federation_provider OWNER TO dbuser;

--
-- Name: user_group_membership; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_group_membership OWNER TO dbuser;

--
-- Name: user_required_action; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_required_action (
    user_id character varying(36) NOT NULL,
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL
);


ALTER TABLE public.user_required_action OWNER TO dbuser;

--
-- Name: user_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_role_mapping (
    role_id character varying(255) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_role_mapping OWNER TO dbuser;

--
-- Name: user_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_session (
    id character varying(36) NOT NULL,
    auth_method character varying(255),
    ip_address character varying(255),
    last_session_refresh integer,
    login_username character varying(255),
    realm_id character varying(255),
    remember_me boolean DEFAULT false NOT NULL,
    started integer,
    user_id character varying(255),
    user_session_state integer,
    broker_session_id character varying(255),
    broker_user_id character varying(255)
);


ALTER TABLE public.user_session OWNER TO dbuser;

--
-- Name: user_session_note; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_session_note (
    user_session character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(2048)
);


ALTER TABLE public.user_session_note OWNER TO dbuser;

--
-- Name: username_login_failure; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.username_login_failure (
    realm_id character varying(36) NOT NULL,
    username character varying(255) NOT NULL,
    failed_login_not_before integer,
    last_failure bigint,
    last_ip_failure character varying(255),
    num_failures integer
);


ALTER TABLE public.username_login_failure OWNER TO dbuser;

--
-- Name: web_origins; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.web_origins (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.web_origins OWNER TO dbuser;

--
-- Data for Name: admin_event_entity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.admin_event_entity (id, admin_event_time, realm_id, operation_type, auth_realm_id, auth_client_id, auth_user_id, ip_address, resource_path, representation, error, resource_type) FROM stdin;
\.


--
-- Data for Name: associated_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.associated_policy (policy_id, associated_policy_id) FROM stdin;
\.


--
-- Data for Name: authentication_execution; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authentication_execution (id, alias, authenticator, realm_id, flow_id, requirement, priority, authenticator_flow, auth_flow_id, auth_config) FROM stdin;
fdfea7a1-5a7c-45c0-bf01-7cc8ae8318cd	\N	auth-cookie	master	5846cdc0-2f0f-4eba-b066-51ee5932bb52	2	10	f	\N	\N
4443ac26-e9a4-40ee-9cf1-de9d24f6cec4	\N	auth-spnego	master	5846cdc0-2f0f-4eba-b066-51ee5932bb52	3	20	f	\N	\N
29b954ef-e1bd-43d9-9d77-abba8c8d263d	\N	identity-provider-redirector	master	5846cdc0-2f0f-4eba-b066-51ee5932bb52	2	25	f	\N	\N
dd8caa97-0406-48a1-960a-453a6fe742bb	\N	\N	master	5846cdc0-2f0f-4eba-b066-51ee5932bb52	2	30	t	6f4fe39c-5b90-4fe5-aa90-aadbdc6b6d9f	\N
932d22ae-388d-4a99-91fb-3915e6a28fe3	\N	auth-username-password-form	master	6f4fe39c-5b90-4fe5-aa90-aadbdc6b6d9f	0	10	f	\N	\N
f9a6e5bc-2a8d-4f7a-a905-c6fefdf6cb99	\N	auth-otp-form	master	6f4fe39c-5b90-4fe5-aa90-aadbdc6b6d9f	1	20	f	\N	\N
59e2fa40-780f-43d2-9e6b-0d085bd7873e	\N	direct-grant-validate-username	master	d7e087bf-6711-4e74-b170-9138ee76617c	0	10	f	\N	\N
69d924df-2dd4-42e2-9221-3eed445cf8f3	\N	direct-grant-validate-password	master	d7e087bf-6711-4e74-b170-9138ee76617c	0	20	f	\N	\N
a4ede487-b079-492e-bfce-f26625e69e1f	\N	direct-grant-validate-otp	master	d7e087bf-6711-4e74-b170-9138ee76617c	1	30	f	\N	\N
9e332e67-85f3-4a34-b614-aad8a36648a5	\N	registration-page-form	master	f9c125ed-5473-494f-8840-0dea1559a4db	0	10	t	ab3d63da-a25d-4539-acff-5255c75b4618	\N
efa48d24-0c9a-47e5-808a-6346ab635185	\N	registration-user-creation	master	ab3d63da-a25d-4539-acff-5255c75b4618	0	20	f	\N	\N
68bb2517-d697-4b7b-83b6-66be54def369	\N	registration-profile-action	master	ab3d63da-a25d-4539-acff-5255c75b4618	0	40	f	\N	\N
6aaa7265-1463-4fc2-8b4b-a75efa1b2e63	\N	registration-password-action	master	ab3d63da-a25d-4539-acff-5255c75b4618	0	50	f	\N	\N
cbad96ec-e7ae-432a-9c21-dd9c53860eba	\N	registration-recaptcha-action	master	ab3d63da-a25d-4539-acff-5255c75b4618	3	60	f	\N	\N
fd73c65c-dfd9-4c4b-b82c-91b122b89e76	\N	reset-credentials-choose-user	master	c83d244b-a57c-4939-90cf-95b7f38006b9	0	10	f	\N	\N
688901ff-c418-436e-8112-35cf9a075ac8	\N	reset-credential-email	master	c83d244b-a57c-4939-90cf-95b7f38006b9	0	20	f	\N	\N
1b89085a-7db7-48dc-b682-6d84141680d9	\N	reset-password	master	c83d244b-a57c-4939-90cf-95b7f38006b9	0	30	f	\N	\N
d1406050-bafb-446c-8067-86a3c4d4da6d	\N	reset-otp	master	c83d244b-a57c-4939-90cf-95b7f38006b9	1	40	f	\N	\N
69874863-3c98-4c3f-ba1c-a9691890c48c	\N	client-secret	master	4074ff48-6dc2-4e39-b15c-97bbc4bad36a	2	10	f	\N	\N
436f30f2-1668-406a-a80a-b80fced94a99	\N	client-jwt	master	4074ff48-6dc2-4e39-b15c-97bbc4bad36a	2	20	f	\N	\N
54427ea7-7909-4e79-8404-ce14de60c540	\N	client-secret-jwt	master	4074ff48-6dc2-4e39-b15c-97bbc4bad36a	2	30	f	\N	\N
0730a105-82d6-4f31-b615-a65cd7b0eed7	\N	client-x509	master	4074ff48-6dc2-4e39-b15c-97bbc4bad36a	2	40	f	\N	\N
2ad93411-607a-4815-8dad-dfa3ec1300fa	\N	idp-review-profile	master	d402875e-bebc-408e-bbd8-437461b45ace	0	10	f	\N	35c12f3b-3525-4581-925a-60ced644c30c
2701dff1-acda-427d-9193-53f7ac989d89	\N	idp-create-user-if-unique	master	d402875e-bebc-408e-bbd8-437461b45ace	2	20	f	\N	5e73e78c-e536-4f90-9c8f-d2afaa704a11
1c27eff5-90b1-42df-b3f5-7c6978e75569	\N	\N	master	d402875e-bebc-408e-bbd8-437461b45ace	2	30	t	58272cf8-8661-486c-a12d-312cbee1e6bc	\N
2432884b-60e7-4f59-ad72-314dd91a0fd5	\N	idp-confirm-link	master	58272cf8-8661-486c-a12d-312cbee1e6bc	0	10	f	\N	\N
30e34dee-5b0d-436d-81aa-40bc377c7721	\N	idp-email-verification	master	58272cf8-8661-486c-a12d-312cbee1e6bc	2	20	f	\N	\N
80bd0cd8-2b6a-4a41-bb07-d73db025900d	\N	\N	master	58272cf8-8661-486c-a12d-312cbee1e6bc	2	30	t	96ee24ad-b4d4-46fe-a30f-e8608baedb2d	\N
4ee7de8d-e18a-4028-8c48-1ac794599345	\N	idp-username-password-form	master	96ee24ad-b4d4-46fe-a30f-e8608baedb2d	0	10	f	\N	\N
ff473b10-81f2-4e01-80ec-b7f3b38596cc	\N	auth-otp-form	master	96ee24ad-b4d4-46fe-a30f-e8608baedb2d	1	20	f	\N	\N
9af7ea51-94d2-46fd-9d7f-0b15239a7df3	\N	http-basic-authenticator	master	f8c7346a-d37f-4d07-950e-0d6ef2ca9271	0	10	f	\N	\N
b67c2f1e-160d-4254-9f5c-476aa068839c	\N	docker-http-basic-authenticator	master	20644fe1-70a0-4f0e-a2ab-032bcb61741c	0	10	f	\N	\N
37a316d6-6cd2-47a6-b9f8-65a67f803e02	\N	no-cookie-redirect	master	d428bcc9-9391-4f3c-a130-c71385a10326	0	10	f	\N	\N
87a688e2-3bfc-4a38-b4b2-ece436a6db46	\N	basic-auth	master	d428bcc9-9391-4f3c-a130-c71385a10326	0	20	f	\N	\N
ed883915-ca91-4cec-869f-635878c0d7f1	\N	basic-auth-otp	master	d428bcc9-9391-4f3c-a130-c71385a10326	3	30	f	\N	\N
a66c89b6-c5fc-4d74-9c57-5c7bfbc93888	\N	auth-spnego	master	d428bcc9-9391-4f3c-a130-c71385a10326	3	40	f	\N	\N
\.


--
-- Data for Name: authentication_flow; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authentication_flow (id, alias, description, realm_id, provider_id, top_level, built_in) FROM stdin;
5846cdc0-2f0f-4eba-b066-51ee5932bb52	browser	browser based authentication	master	basic-flow	t	t
6f4fe39c-5b90-4fe5-aa90-aadbdc6b6d9f	forms	Username, password, otp and other auth forms.	master	basic-flow	f	t
d7e087bf-6711-4e74-b170-9138ee76617c	direct grant	OpenID Connect Resource Owner Grant	master	basic-flow	t	t
f9c125ed-5473-494f-8840-0dea1559a4db	registration	registration flow	master	basic-flow	t	t
ab3d63da-a25d-4539-acff-5255c75b4618	registration form	registration form	master	form-flow	f	t
c83d244b-a57c-4939-90cf-95b7f38006b9	reset credentials	Reset credentials for a user if they forgot their password or something	master	basic-flow	t	t
4074ff48-6dc2-4e39-b15c-97bbc4bad36a	clients	Base authentication for clients	master	client-flow	t	t
d402875e-bebc-408e-bbd8-437461b45ace	first broker login	Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account	master	basic-flow	t	t
58272cf8-8661-486c-a12d-312cbee1e6bc	Handle Existing Account	Handle what to do if there is existing account with same email/username like authenticated identity provider	master	basic-flow	f	t
96ee24ad-b4d4-46fe-a30f-e8608baedb2d	Verify Existing Account by Re-authentication	Reauthentication of existing account	master	basic-flow	f	t
f8c7346a-d37f-4d07-950e-0d6ef2ca9271	saml ecp	SAML ECP Profile Authentication Flow	master	basic-flow	t	t
20644fe1-70a0-4f0e-a2ab-032bcb61741c	docker auth	Used by Docker clients to authenticate against the IDP	master	basic-flow	t	t
d428bcc9-9391-4f3c-a130-c71385a10326	http challenge	An authentication flow based on challenge-response HTTP Authentication Schemes	master	basic-flow	t	t
\.


--
-- Data for Name: authenticator_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authenticator_config (id, alias, realm_id) FROM stdin;
35c12f3b-3525-4581-925a-60ced644c30c	review profile config	master
5e73e78c-e536-4f90-9c8f-d2afaa704a11	create unique user config	master
\.


--
-- Data for Name: authenticator_config_entry; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authenticator_config_entry (authenticator_id, value, name) FROM stdin;
35c12f3b-3525-4581-925a-60ced644c30c	missing	update.profile.on.first.login
5e73e78c-e536-4f90-9c8f-d2afaa704a11	false	require.password.update.after.registration
\.


--
-- Data for Name: broker_link; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.broker_link (identity_provider, storage_provider_id, realm_id, broker_user_id, broker_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: client; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client (id, enabled, full_scope_allowed, client_id, not_before, public_client, secret, base_url, bearer_only, management_url, surrogate_auth_required, realm_id, protocol, node_rereg_timeout, frontchannel_logout, consent_required, name, service_accounts_enabled, client_authenticator_type, root_url, description, registration_token, standard_flow_enabled, implicit_flow_enabled, direct_access_grants_enabled) FROM stdin;
8660773b-92db-46c8-a9ef-93ecc53f24d8	t	t	master-realm	0	f	9ed0158d-0e31-4383-8150-f10554ccc4b3	\N	t	\N	f	master	\N	0	f	f	master Realm	f	client-secret	\N	\N	\N	t	f	f
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	t	f	account	0	f	46786652-8a5c-4b3c-b7c5-de46df2da709	/auth/realms/master/account	f	\N	f	master	openid-connect	0	f	f	${client_account}	f	client-secret	\N	\N	\N	t	f	f
bfdd8008-8b63-4961-b9b9-09e28839bf14	t	f	broker	0	f	f2364a79-3827-4e00-9994-44a7c6cac689	\N	f	\N	f	master	openid-connect	0	f	f	${client_broker}	f	client-secret	\N	\N	\N	t	f	f
0bce9c9c-c9b8-457f-ba02-efced1af0df6	t	f	security-admin-console	0	t	864e9c47-f3a8-4667-b832-966ed83b48d3	/auth/admin/master/console/index.html	f	\N	f	master	openid-connect	0	f	f	${client_security-admin-console}	f	client-secret	\N	\N	\N	t	f	f
ccdcaeee-6cc8-4845-b5d1-54191cfee1d8	t	f	admin-cli	0	t	d8b31a3e-aaca-406d-8780-6591b8ba99f9	\N	f	\N	f	master	openid-connect	0	f	f	${client_admin-cli}	f	client-secret	\N	\N	\N	f	f	t
d5a33898-5c96-4b96-8f29-c1bec691def4	t	t	idp-flaminem	0	f	0f5232ad-02eb-4ebf-b70a-501f23255546	/broker/keycloak-oidc	f	\N	f	master	openid-connect	-1	f	f	idp-flaminem	f	client-secret	http://keycloak-flaminem.localtest.me:8080/auth/realms/master	keycloak to keycloak SSO for flaminem	\N	t	f	t
\.


--
-- Data for Name: client_attributes; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_attributes (client_id, value, name) FROM stdin;
d5a33898-5c96-4b96-8f29-c1bec691def4	false	saml.server.signature
d5a33898-5c96-4b96-8f29-c1bec691def4	false	saml.server.signature.keyinfo.ext
d5a33898-5c96-4b96-8f29-c1bec691def4	false	saml.assertion.signature
d5a33898-5c96-4b96-8f29-c1bec691def4	false	saml.client.signature
d5a33898-5c96-4b96-8f29-c1bec691def4	false	saml.encrypt
d5a33898-5c96-4b96-8f29-c1bec691def4	false	saml.authnstatement
d5a33898-5c96-4b96-8f29-c1bec691def4	false	saml.onetimeuse.condition
d5a33898-5c96-4b96-8f29-c1bec691def4	false	saml_force_name_id_format
d5a33898-5c96-4b96-8f29-c1bec691def4	false	saml.multivalued.roles
d5a33898-5c96-4b96-8f29-c1bec691def4	false	saml.force.post.binding
d5a33898-5c96-4b96-8f29-c1bec691def4	false	exclude.session.state.from.auth.response
d5a33898-5c96-4b96-8f29-c1bec691def4	false	tls.client.certificate.bound.access.tokens
d5a33898-5c96-4b96-8f29-c1bec691def4	false	display.on.consent.screen
\.


--
-- Data for Name: client_auth_flow_bindings; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_auth_flow_bindings (client_id, flow_id, binding_name) FROM stdin;
\.


--
-- Data for Name: client_default_roles; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_default_roles (client_id, role_id) FROM stdin;
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	a18b0b30-b25d-41f1-8ad2-05a076abd1ec
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	ccbb3f8b-7022-41cc-be8d-b78c487bcf55
\.


--
-- Data for Name: client_initial_access; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_initial_access (id, realm_id, "timestamp", expiration, count, remaining_count) FROM stdin;
\.


--
-- Data for Name: client_node_registrations; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_node_registrations (client_id, value, name) FROM stdin;
\.


--
-- Data for Name: client_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope (id, name, realm_id, description, protocol) FROM stdin;
671a5049-fab0-4a2c-9fe0-a59120aaf323	offline_access	master	OpenID Connect built-in scope: offline_access	openid-connect
42a3deed-4e91-484a-a75c-b63cff67e67a	role_list	master	SAML role list	saml
26cf9780-ae5f-4740-83f6-120a23a2bc94	profile	master	OpenID Connect built-in scope: profile	openid-connect
0c316958-1718-4d46-a024-d1fad4693feb	email	master	OpenID Connect built-in scope: email	openid-connect
e20c2763-240b-443e-a71d-1ebccaf79387	address	master	OpenID Connect built-in scope: address	openid-connect
6dc72d0e-f25a-4962-8040-351ace0aa19a	phone	master	OpenID Connect built-in scope: phone	openid-connect
06b0e688-b570-4424-ac5e-8224791da759	roles	master	OpenID Connect scope for add user roles to the access token	openid-connect
8888ca84-252e-41ec-929e-8776aeced16b	web-origins	master	OpenID Connect scope for add allowed web origins to the access token	openid-connect
3884a85d-5aed-4209-90e1-87b4978f9ef5	microprofile-jwt	master	Microprofile - JWT built-in scope	openid-connect
\.


--
-- Data for Name: client_scope_attributes; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope_attributes (scope_id, value, name) FROM stdin;
671a5049-fab0-4a2c-9fe0-a59120aaf323	true	display.on.consent.screen
671a5049-fab0-4a2c-9fe0-a59120aaf323	${offlineAccessScopeConsentText}	consent.screen.text
42a3deed-4e91-484a-a75c-b63cff67e67a	true	display.on.consent.screen
42a3deed-4e91-484a-a75c-b63cff67e67a	${samlRoleListScopeConsentText}	consent.screen.text
26cf9780-ae5f-4740-83f6-120a23a2bc94	true	display.on.consent.screen
26cf9780-ae5f-4740-83f6-120a23a2bc94	${profileScopeConsentText}	consent.screen.text
26cf9780-ae5f-4740-83f6-120a23a2bc94	true	include.in.token.scope
0c316958-1718-4d46-a024-d1fad4693feb	true	display.on.consent.screen
0c316958-1718-4d46-a024-d1fad4693feb	${emailScopeConsentText}	consent.screen.text
0c316958-1718-4d46-a024-d1fad4693feb	true	include.in.token.scope
e20c2763-240b-443e-a71d-1ebccaf79387	true	display.on.consent.screen
e20c2763-240b-443e-a71d-1ebccaf79387	${addressScopeConsentText}	consent.screen.text
e20c2763-240b-443e-a71d-1ebccaf79387	true	include.in.token.scope
6dc72d0e-f25a-4962-8040-351ace0aa19a	true	display.on.consent.screen
6dc72d0e-f25a-4962-8040-351ace0aa19a	${phoneScopeConsentText}	consent.screen.text
6dc72d0e-f25a-4962-8040-351ace0aa19a	true	include.in.token.scope
06b0e688-b570-4424-ac5e-8224791da759	true	display.on.consent.screen
06b0e688-b570-4424-ac5e-8224791da759	${rolesScopeConsentText}	consent.screen.text
06b0e688-b570-4424-ac5e-8224791da759	false	include.in.token.scope
8888ca84-252e-41ec-929e-8776aeced16b	false	display.on.consent.screen
8888ca84-252e-41ec-929e-8776aeced16b		consent.screen.text
8888ca84-252e-41ec-929e-8776aeced16b	false	include.in.token.scope
3884a85d-5aed-4209-90e1-87b4978f9ef5	false	display.on.consent.screen
3884a85d-5aed-4209-90e1-87b4978f9ef5	true	include.in.token.scope
\.


--
-- Data for Name: client_scope_client; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope_client (client_id, scope_id, default_scope) FROM stdin;
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	42a3deed-4e91-484a-a75c-b63cff67e67a	t
ccdcaeee-6cc8-4845-b5d1-54191cfee1d8	42a3deed-4e91-484a-a75c-b63cff67e67a	t
bfdd8008-8b63-4961-b9b9-09e28839bf14	42a3deed-4e91-484a-a75c-b63cff67e67a	t
8660773b-92db-46c8-a9ef-93ecc53f24d8	42a3deed-4e91-484a-a75c-b63cff67e67a	t
0bce9c9c-c9b8-457f-ba02-efced1af0df6	42a3deed-4e91-484a-a75c-b63cff67e67a	t
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	26cf9780-ae5f-4740-83f6-120a23a2bc94	t
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	0c316958-1718-4d46-a024-d1fad4693feb	t
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	06b0e688-b570-4424-ac5e-8224791da759	t
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	8888ca84-252e-41ec-929e-8776aeced16b	t
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	671a5049-fab0-4a2c-9fe0-a59120aaf323	f
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	e20c2763-240b-443e-a71d-1ebccaf79387	f
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	6dc72d0e-f25a-4962-8040-351ace0aa19a	f
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	3884a85d-5aed-4209-90e1-87b4978f9ef5	f
ccdcaeee-6cc8-4845-b5d1-54191cfee1d8	26cf9780-ae5f-4740-83f6-120a23a2bc94	t
ccdcaeee-6cc8-4845-b5d1-54191cfee1d8	0c316958-1718-4d46-a024-d1fad4693feb	t
ccdcaeee-6cc8-4845-b5d1-54191cfee1d8	06b0e688-b570-4424-ac5e-8224791da759	t
ccdcaeee-6cc8-4845-b5d1-54191cfee1d8	8888ca84-252e-41ec-929e-8776aeced16b	t
ccdcaeee-6cc8-4845-b5d1-54191cfee1d8	671a5049-fab0-4a2c-9fe0-a59120aaf323	f
ccdcaeee-6cc8-4845-b5d1-54191cfee1d8	e20c2763-240b-443e-a71d-1ebccaf79387	f
ccdcaeee-6cc8-4845-b5d1-54191cfee1d8	6dc72d0e-f25a-4962-8040-351ace0aa19a	f
ccdcaeee-6cc8-4845-b5d1-54191cfee1d8	3884a85d-5aed-4209-90e1-87b4978f9ef5	f
bfdd8008-8b63-4961-b9b9-09e28839bf14	26cf9780-ae5f-4740-83f6-120a23a2bc94	t
bfdd8008-8b63-4961-b9b9-09e28839bf14	0c316958-1718-4d46-a024-d1fad4693feb	t
bfdd8008-8b63-4961-b9b9-09e28839bf14	06b0e688-b570-4424-ac5e-8224791da759	t
bfdd8008-8b63-4961-b9b9-09e28839bf14	8888ca84-252e-41ec-929e-8776aeced16b	t
bfdd8008-8b63-4961-b9b9-09e28839bf14	671a5049-fab0-4a2c-9fe0-a59120aaf323	f
bfdd8008-8b63-4961-b9b9-09e28839bf14	e20c2763-240b-443e-a71d-1ebccaf79387	f
bfdd8008-8b63-4961-b9b9-09e28839bf14	6dc72d0e-f25a-4962-8040-351ace0aa19a	f
bfdd8008-8b63-4961-b9b9-09e28839bf14	3884a85d-5aed-4209-90e1-87b4978f9ef5	f
8660773b-92db-46c8-a9ef-93ecc53f24d8	26cf9780-ae5f-4740-83f6-120a23a2bc94	t
8660773b-92db-46c8-a9ef-93ecc53f24d8	0c316958-1718-4d46-a024-d1fad4693feb	t
8660773b-92db-46c8-a9ef-93ecc53f24d8	06b0e688-b570-4424-ac5e-8224791da759	t
8660773b-92db-46c8-a9ef-93ecc53f24d8	8888ca84-252e-41ec-929e-8776aeced16b	t
8660773b-92db-46c8-a9ef-93ecc53f24d8	671a5049-fab0-4a2c-9fe0-a59120aaf323	f
8660773b-92db-46c8-a9ef-93ecc53f24d8	e20c2763-240b-443e-a71d-1ebccaf79387	f
8660773b-92db-46c8-a9ef-93ecc53f24d8	6dc72d0e-f25a-4962-8040-351ace0aa19a	f
8660773b-92db-46c8-a9ef-93ecc53f24d8	3884a85d-5aed-4209-90e1-87b4978f9ef5	f
0bce9c9c-c9b8-457f-ba02-efced1af0df6	26cf9780-ae5f-4740-83f6-120a23a2bc94	t
0bce9c9c-c9b8-457f-ba02-efced1af0df6	0c316958-1718-4d46-a024-d1fad4693feb	t
0bce9c9c-c9b8-457f-ba02-efced1af0df6	06b0e688-b570-4424-ac5e-8224791da759	t
0bce9c9c-c9b8-457f-ba02-efced1af0df6	8888ca84-252e-41ec-929e-8776aeced16b	t
0bce9c9c-c9b8-457f-ba02-efced1af0df6	671a5049-fab0-4a2c-9fe0-a59120aaf323	f
0bce9c9c-c9b8-457f-ba02-efced1af0df6	e20c2763-240b-443e-a71d-1ebccaf79387	f
0bce9c9c-c9b8-457f-ba02-efced1af0df6	6dc72d0e-f25a-4962-8040-351ace0aa19a	f
0bce9c9c-c9b8-457f-ba02-efced1af0df6	3884a85d-5aed-4209-90e1-87b4978f9ef5	f
d5a33898-5c96-4b96-8f29-c1bec691def4	42a3deed-4e91-484a-a75c-b63cff67e67a	t
d5a33898-5c96-4b96-8f29-c1bec691def4	26cf9780-ae5f-4740-83f6-120a23a2bc94	t
d5a33898-5c96-4b96-8f29-c1bec691def4	0c316958-1718-4d46-a024-d1fad4693feb	t
d5a33898-5c96-4b96-8f29-c1bec691def4	06b0e688-b570-4424-ac5e-8224791da759	t
d5a33898-5c96-4b96-8f29-c1bec691def4	8888ca84-252e-41ec-929e-8776aeced16b	t
d5a33898-5c96-4b96-8f29-c1bec691def4	671a5049-fab0-4a2c-9fe0-a59120aaf323	f
d5a33898-5c96-4b96-8f29-c1bec691def4	e20c2763-240b-443e-a71d-1ebccaf79387	f
d5a33898-5c96-4b96-8f29-c1bec691def4	6dc72d0e-f25a-4962-8040-351ace0aa19a	f
d5a33898-5c96-4b96-8f29-c1bec691def4	3884a85d-5aed-4209-90e1-87b4978f9ef5	f
\.


--
-- Data for Name: client_scope_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope_role_mapping (scope_id, role_id) FROM stdin;
671a5049-fab0-4a2c-9fe0-a59120aaf323	cec463df-65c7-454b-bddd-467f0eb38cc5
\.


--
-- Data for Name: client_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session (id, client_id, redirect_uri, state, "timestamp", session_id, auth_method, realm_id, auth_user_id, current_action) FROM stdin;
\.


--
-- Data for Name: client_session_auth_status; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_auth_status (authenticator, status, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_note; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_note (name, value, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_prot_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_prot_mapper (protocol_mapper_id, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_role; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_role (role_id, client_session) FROM stdin;
\.


--
-- Data for Name: client_user_session_note; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_user_session_note (name, value, client_session) FROM stdin;
\.


--
-- Data for Name: component; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.component (id, name, parent_id, provider_id, provider_type, realm_id, sub_type) FROM stdin;
89653f9d-d041-436b-83e5-43b1e949b1e1	Trusted Hosts	master	trusted-hosts	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
eecb396f-9b28-4489-8673-0cb4198255a8	Consent Required	master	consent-required	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
e45edbea-a0d8-4663-bd0a-8ac379014de9	Full Scope Disabled	master	scope	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
03598933-8c2c-4402-b4b3-662e3ba844aa	Max Clients Limit	master	max-clients	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
7adeef5b-67cf-4677-a4a0-e710bf53054f	Allowed Protocol Mapper Types	master	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
f726a2ce-2b89-4e78-a73d-f5bf798a7185	Allowed Client Scopes	master	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
b6c8d0c8-6a44-4448-a852-35b71b9c5184	Allowed Protocol Mapper Types	master	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	authenticated
4134c598-b375-43b7-8008-705c0311a45e	Allowed Client Scopes	master	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	authenticated
3fe8c3f2-6144-40b3-9861-b9bb62d36d4d	rsa-generated	master	rsa-generated	org.keycloak.keys.KeyProvider	master	\N
77b0be59-c472-4275-9ef8-d656a062f8c3	hmac-generated	master	hmac-generated	org.keycloak.keys.KeyProvider	master	\N
a91fb4c8-e415-4b07-aae7-ae49f48299ed	aes-generated	master	aes-generated	org.keycloak.keys.KeyProvider	master	\N
\.


--
-- Data for Name: component_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.component_config (id, component_id, name, value) FROM stdin;
5da1e6c9-6576-4a57-bf46-5a414bd9d98c	b6c8d0c8-6a44-4448-a852-35b71b9c5184	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
f2adb5cd-94aa-448e-b564-6b8c2cbcdbe2	b6c8d0c8-6a44-4448-a852-35b71b9c5184	allowed-protocol-mapper-types	oidc-full-name-mapper
dc087dfa-610d-405d-bbde-617f735eba65	b6c8d0c8-6a44-4448-a852-35b71b9c5184	allowed-protocol-mapper-types	oidc-address-mapper
a7a7f0d3-3bbe-4560-a322-002eb0db1cb3	b6c8d0c8-6a44-4448-a852-35b71b9c5184	allowed-protocol-mapper-types	saml-user-property-mapper
ea5cbf68-cc35-495e-97d3-da3b0b0bca7a	b6c8d0c8-6a44-4448-a852-35b71b9c5184	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
826f685f-77da-44ec-a06a-3cc98bb93196	b6c8d0c8-6a44-4448-a852-35b71b9c5184	allowed-protocol-mapper-types	saml-user-attribute-mapper
9cdffeb0-7c60-48a2-b669-bd72ea8e1537	b6c8d0c8-6a44-4448-a852-35b71b9c5184	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
1a9cb225-d61c-48db-a5a4-97f93d5bc4e4	b6c8d0c8-6a44-4448-a852-35b71b9c5184	allowed-protocol-mapper-types	saml-role-list-mapper
8c7ff5ab-a04c-46bd-b16b-0e9c0d30ab96	4134c598-b375-43b7-8008-705c0311a45e	allow-default-scopes	true
c64d3218-c5ad-4e1d-93a6-04428de35d6a	89653f9d-d041-436b-83e5-43b1e949b1e1	client-uris-must-match	true
2565a59a-0e55-4140-8c59-1f499d67fd37	89653f9d-d041-436b-83e5-43b1e949b1e1	host-sending-registration-request-must-match	true
8236087b-4b3c-4144-8c07-aa4eaf7dce3c	f726a2ce-2b89-4e78-a73d-f5bf798a7185	allow-default-scopes	true
2d243fa6-8b55-4948-8e1b-63e69975b8af	7adeef5b-67cf-4677-a4a0-e710bf53054f	allowed-protocol-mapper-types	oidc-full-name-mapper
9ad9d55f-0e47-4393-924a-8bef4c184f56	7adeef5b-67cf-4677-a4a0-e710bf53054f	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
9c3c184a-5237-4c06-bb3e-52411763d91a	7adeef5b-67cf-4677-a4a0-e710bf53054f	allowed-protocol-mapper-types	saml-role-list-mapper
d5a9348d-aae8-47ca-b3e3-f491356b8184	7adeef5b-67cf-4677-a4a0-e710bf53054f	allowed-protocol-mapper-types	saml-user-attribute-mapper
014bcba5-5e96-4910-8e58-77b7ac98d13f	7adeef5b-67cf-4677-a4a0-e710bf53054f	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
60858c6c-70a9-47d8-9317-be0c9d618c3f	7adeef5b-67cf-4677-a4a0-e710bf53054f	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
d03844dd-5827-4c8d-9c8b-86f46c290a64	7adeef5b-67cf-4677-a4a0-e710bf53054f	allowed-protocol-mapper-types	oidc-address-mapper
47ee3152-bde7-4278-962a-c3f844bb909a	7adeef5b-67cf-4677-a4a0-e710bf53054f	allowed-protocol-mapper-types	saml-user-property-mapper
236cff02-59b6-4a2b-b86e-a95d1432be8f	03598933-8c2c-4402-b4b3-662e3ba844aa	max-clients	200
f2037171-6796-4f8e-a0fd-5e5c54233ab2	3fe8c3f2-6144-40b3-9861-b9bb62d36d4d	certificate	MIICmzCCAYMCBgFtBoVgijANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMTkwOTA2MTIxOTI3WhcNMjkwOTA2MTIyMTA3WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCLCYjFi1JkrgP+DkaFqXiechjctjwoI2Drsi8znwkIayaob7vBvqLRgkZ4n7EUlzRwubSozpL7aLVe7mXhfFLR60GU/rtVmVAlxTnbTnY52cDkpVnu8zi6+6kclHp5SOAqUWk3v9cdGrpvP4MS5JJqMBODJVq0WhEeXE7J5X4RA1VSd3oY7UNTzfJ6YFY3RbcPjz9da0vODjEfhKiFqcibvRD18TqHlp1oI07oK1vuw0lmO91u8YMzXgfNxAzwC+3OMw5Ci59lMQorcyIXlGq7JzZDDKyH8TPFUNs+1TrfYGHeyLo7VdDwyKoO3MRKV3WFXhV6/r+PowAqgnpTeAJFAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHBCKTunQZRovBlR63LoCJgxRv4rDKLCkogziSPDqf1fxEtxywruHFCSxhtgFFlYXy4iPCNDNJK0HhiDLZ6+qlHpzd6CFKlEENff/1caOFC7sqbS3pxFPAbhpDGyWyXNkQ222We/hNMoKghjiwhwSKd0n36UFyH/RUpTO6AqmDSRw98I/alRs++4HGZyt7R3nYgaUwzPaSeOddgMBEjWEy5nFhp8cWeT7a8UlSWgqUaGjuAv1G91zCFIX1aHgzkKbsT3MG3G43NseYITeb9XBf1HSYVlDyF+//mf6iSjcHq/onBVfLjjb4x7Lcy2a5Ks9/YElM8VtRB0xauffkk5Hxo=
604f4031-b2c8-4f0d-b254-dfe3fe7e9492	3fe8c3f2-6144-40b3-9861-b9bb62d36d4d	privateKey	MIIEogIBAAKCAQEAiwmIxYtSZK4D/g5Ghal4nnIY3LY8KCNg67IvM58JCGsmqG+7wb6i0YJGeJ+xFJc0cLm0qM6S+2i1Xu5l4XxS0etBlP67VZlQJcU52052OdnA5KVZ7vM4uvupHJR6eUjgKlFpN7/XHRq6bz+DEuSSajATgyVatFoRHlxOyeV+EQNVUnd6GO1DU83yemBWN0W3D48/XWtLzg4xH4SohanIm70Q9fE6h5adaCNO6Ctb7sNJZjvdbvGDM14HzcQM8AvtzjMOQoufZTEKK3MiF5Rquyc2Qwysh/EzxVDbPtU632Bh3si6O1XQ8MiqDtzESld1hV4Vev6/j6MAKoJ6U3gCRQIDAQABAoIBAFLQI/ndqP60s0YQRKr6LRDazrovhRc3M1RPtlOd5yhvggATRRb6MEpvuP/BxhyIj0CRK+zb1aoPTPA1ONOcVEwaPt669uPeRGGq3nIkgsCkVYMahb2QevrMSIbwXR5+bJ5oDS6agksgj2kRwEVxhU/gQM79YdBIUSfvPTJ+EZ+ZpuIai7ItnMLZBygZWuRAjsTZ5XfR+6Z974Sji2mOpQ5nEzXkSMkTLBowlfdvX7OVMwQq2pmG/M/pXO1p6UVqkOgjMu2IWbnpn6F6aLkbvR1uVQdD4+0M9vGUWvMFCRtQpfxeHvzx/esUCJvP9vHirghRt7X5hJeEhtK9HElb0qECgYEAv++wUNUP5P0w8pP8XU95COFeDNT6Bi6xhn1ooZMweHD7vrP2Vli5p2NdszsQW3tHKkoKGYLFLAnYqO0n+kZDMUt1TrV+WzfDRzeD7hg2Uz4yvyUbSGFNdtD8Vl/aQuSwSNSQ+tQcOLV5r3+WnVW750+DZVQxw5DmhA5jHodWickCgYEAuXHMzyMoKKgD55Fx9FfxLT5DErApoitAX9OSNmHP9n1ZNlA6UWa4QOXifvveD9mfiC74ryMWfiohNu7IdFUlFJvzRqbqZQNB0xDUYp+AyINQQEego32W0zPvs+C7QuXktLL3b3pQ6qRK8o9FMJBz+Hx85hn6WAUNEeeDTj66cp0CgYBu/yIr3MtQVcvUvRgYrjkElbBaI2Bj6uTnLecwaXqCbHRpmJFA5haXYrNxTxrqjKRfJGoqzqFQEnGlX2DbL370Jvs0BWmJPvpDWSuGqaHhCfs25zKb7QlrSPhkyxHh1XbM54DgTYH0mZ5Bi7uCSW5dGnKWStZsjoOAowFXSlUVYQKBgHYv+P/qwCVpL1PedmnrwmG7VLQMYfxg5F4uUPknzYqiyMC80O4gMT3rRTb4/sXLRMleZk/4ZNVztEd2V3sM6N0Bp0JYDvrh4InMKA/S6Bji17qf69lGqWFhsFtL1w0Dx4cCqH/7zKY+nyWH+ejBp6eub0uXMt32GiZXDnBHujxhAoGABlnsVlRp4//vOowCO4bBu0cyVhAiZciTUt4tODZ6aJxVOLoUzFuZT0obW4F2cScqNAlv62bBbsKqJsEvTovccASBZ8+IbvR0gRB8wpP/pK6nX6peFOpu9V7J5psfkQw9+0uRUI61h8UHAjGfa681NOVMGUDwUXVe/qV/BuiSK0s=
6da91ceb-6a99-4fab-ab47-b5262a46568f	3fe8c3f2-6144-40b3-9861-b9bb62d36d4d	priority	100
830f54a0-24b4-494b-a630-b397e8e51b46	a91fb4c8-e415-4b07-aae7-ae49f48299ed	kid	e24ea8cb-e9f7-4128-849f-e1becd842d8f
4609be8e-6f48-4fd7-a5f1-c787043c513b	a91fb4c8-e415-4b07-aae7-ae49f48299ed	secret	oS-8VnCdlbCNP-gPmsHIvQ
0e6572bf-b94a-4ad7-a361-fb9fb85c195a	a91fb4c8-e415-4b07-aae7-ae49f48299ed	priority	100
6ddeecd7-8629-4746-94bd-6e08c2f61b99	77b0be59-c472-4275-9ef8-d656a062f8c3	algorithm	HS256
5ea8c20f-6c03-43df-b306-df22f628c951	77b0be59-c472-4275-9ef8-d656a062f8c3	priority	100
2de9a485-fb8b-48ed-86cd-e559f31cef72	77b0be59-c472-4275-9ef8-d656a062f8c3	kid	3bf9fee9-73f2-4768-9a51-3967f7863519
70a90430-083d-40a7-850a-a5926cd37063	77b0be59-c472-4275-9ef8-d656a062f8c3	secret	m4LEe6UT6ExKmTw7ooJXLiBiSWyMEwkkqU4cpPrQLC4Pkw6JZ2pjpc0ZqlZgOboGga_5dImiuzIJZJBLfaSd2w
\.


--
-- Data for Name: composite_role; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.composite_role (composite, child_role) FROM stdin;
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	02d4d60d-3d16-4ee0-b6da-b3b037edea09
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	f7884cf5-2c68-4543-aa55-5533b96c4345
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	96e13568-bf75-4449-abae-c36acfd1f05b
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	e2154b31-49cc-4637-bb9b-e6b07aac06cb
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	b6cdf90e-2364-4b39-9c29-e4108f18f567
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	569d276b-64ce-474f-9b0b-2ee46983ba1e
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	309a3441-f553-49f8-a8f8-4c8b179b9e48
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	f0350b21-7be8-4e12-951a-841a39a05697
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	a5eb862d-9a71-442a-bbee-78181eab52b9
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	767bf792-99d8-412b-820c-8bfab54c0ca8
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	6dbe0e1c-dcec-4e01-9c28-aa742be30039
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	f1782dbc-0ac5-47d1-9cb7-c69a7aa578a4
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	75aa5b45-22dc-439b-b4c6-fa8aef64d2d1
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	1100d31c-1130-485e-9e56-83779cf139b5
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	c8848376-9f44-451f-b00a-5e659e91cf84
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	d5129a14-e8ec-444d-8217-587e12692839
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	b4381f40-4573-445a-95ef-1778d7e1fd88
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	d6d25d90-c45d-4ce7-bae7-b71c27603992
e2154b31-49cc-4637-bb9b-e6b07aac06cb	c8848376-9f44-451f-b00a-5e659e91cf84
e2154b31-49cc-4637-bb9b-e6b07aac06cb	d6d25d90-c45d-4ce7-bae7-b71c27603992
b6cdf90e-2364-4b39-9c29-e4108f18f567	d5129a14-e8ec-444d-8217-587e12692839
ccbb3f8b-7022-41cc-be8d-b78c487bcf55	df922ee4-c20b-4441-8fde-8fe7c8573f63
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	af439cfb-c438-4fb6-b884-2e5ae1fe1721
\.


--
-- Data for Name: credential; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.credential (id, device, hash_iterations, salt, type, value, user_id, created_date, counter, digits, period, algorithm) FROM stdin;
1ba40ff5-11cf-447f-9293-0363aaabdbe2	\N	27500	\\x1327c38696fb66ed3407ca65c592c693	password	3sY23BSyumeDO4kGN97qEXluGiGh+n26vmdTPU0YbEhs9YkpPEr8Q3oD/XX/nyChEDD2OxPgvpaSqcG0inRUXg==	301d85b0-5cbf-426a-835c-9a497dec9e36	\N	0	0	0	pbkdf2-sha256
bd3e8bc5-2e6c-4cf7-bf20-b82fd69ab4c1	\N	27500	\\xe8a6f0485f3e7e736b0798cc6a297d30	password	2f3xR915Tjr7cRmmMFL0V8Y1pYXK7U/HtMchC8VKdET7kcNMKaCwIjTE2IFMSbjPlxhlS88etaQlwh0zumpYqA==	f51f95cd-9226-464a-a7ac-d04fd8a66333	1568049037679	0	0	0	pbkdf2-sha256
\.


--
-- Data for Name: credential_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.credential_attribute (id, credential_id, name, value) FROM stdin;
\.


--
-- Data for Name: databasechangelog; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, md5sum, description, comments, tag, liquibase, contexts, labels, deployment_id) FROM stdin;
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/jpa-changelog-1.0.0.Final.xml	2019-09-06 12:20:59.602591	1	EXECUTED	7:4e70412f24a3f382c82183742ec79317	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	3.5.4	\N	\N	7772459249
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/db2-jpa-changelog-1.0.0.Final.xml	2019-09-06 12:20:59.620899	2	MARK_RAN	7:cb16724583e9675711801c6875114f28	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	3.5.4	\N	\N	7772459249
1.1.0.Beta1	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Beta1.xml	2019-09-06 12:20:59.673907	3	EXECUTED	7:0310eb8ba07cec616460794d42ade0fa	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=CLIENT_ATTRIBUTES; createTable tableName=CLIENT_SESSION_NOTE; createTable tableName=APP_NODE_REGISTRATIONS; addColumn table...		\N	3.5.4	\N	\N	7772459249
1.1.0.Final	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Final.xml	2019-09-06 12:20:59.678763	4	EXECUTED	7:5d25857e708c3233ef4439df1f93f012	renameColumn newColumnName=EVENT_TIME, oldColumnName=TIME, tableName=EVENT_ENTITY		\N	3.5.4	\N	\N	7772459249
1.2.0.Beta1	psilva@redhat.com	META-INF/jpa-changelog-1.2.0.Beta1.xml	2019-09-06 12:20:59.785204	5	EXECUTED	7:c7a54a1041d58eb3817a4a883b4d4e84	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	3.5.4	\N	\N	7772459249
1.2.0.Beta1	psilva@redhat.com	META-INF/db2-jpa-changelog-1.2.0.Beta1.xml	2019-09-06 12:20:59.789693	6	MARK_RAN	7:2e01012df20974c1c2a605ef8afe25b7	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	3.5.4	\N	\N	7772459249
1.2.0.RC1	bburke@redhat.com	META-INF/jpa-changelog-1.2.0.CR1.xml	2019-09-06 12:20:59.887142	7	EXECUTED	7:0f08df48468428e0f30ee59a8ec01a41	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	3.5.4	\N	\N	7772459249
1.2.0.RC1	bburke@redhat.com	META-INF/db2-jpa-changelog-1.2.0.CR1.xml	2019-09-06 12:20:59.894986	8	MARK_RAN	7:a77ea2ad226b345e7d689d366f185c8c	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	3.5.4	\N	\N	7772459249
1.2.0.Final	keycloak	META-INF/jpa-changelog-1.2.0.Final.xml	2019-09-06 12:20:59.900313	9	EXECUTED	7:a3377a2059aefbf3b90ebb4c4cc8e2ab	update tableName=CLIENT; update tableName=CLIENT; update tableName=CLIENT		\N	3.5.4	\N	\N	7772459249
1.3.0	bburke@redhat.com	META-INF/jpa-changelog-1.3.0.xml	2019-09-06 12:21:00.033273	10	EXECUTED	7:04c1dbedc2aa3e9756d1a1668e003451	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=ADMI...		\N	3.5.4	\N	\N	7772459249
1.4.0	bburke@redhat.com	META-INF/jpa-changelog-1.4.0.xml	2019-09-06 12:21:00.147474	11	EXECUTED	7:36ef39ed560ad07062d956db861042ba	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	7772459249
1.4.0	bburke@redhat.com	META-INF/db2-jpa-changelog-1.4.0.xml	2019-09-06 12:21:00.15267	12	MARK_RAN	7:d909180b2530479a716d3f9c9eaea3d7	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	7772459249
1.5.0	bburke@redhat.com	META-INF/jpa-changelog-1.5.0.xml	2019-09-06 12:21:00.262062	13	EXECUTED	7:cf12b04b79bea5152f165eb41f3955f6	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	7772459249
1.6.1_from15	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 12:21:00.307513	14	EXECUTED	7:7e32c8f05c755e8675764e7d5f514509	addColumn tableName=REALM; addColumn tableName=KEYCLOAK_ROLE; addColumn tableName=CLIENT; createTable tableName=OFFLINE_USER_SESSION; createTable tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_US_SES_PK2, tableName=...		\N	3.5.4	\N	\N	7772459249
1.6.1_from16-pre	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 12:21:00.309928	15	MARK_RAN	7:980ba23cc0ec39cab731ce903dd01291	delete tableName=OFFLINE_CLIENT_SESSION; delete tableName=OFFLINE_USER_SESSION		\N	3.5.4	\N	\N	7772459249
1.6.1_from16	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 12:21:00.313297	16	MARK_RAN	7:2fa220758991285312eb84f3b4ff5336	dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_US_SES_PK, tableName=OFFLINE_USER_SESSION; dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_CL_SES_PK, tableName=OFFLINE_CLIENT_SESSION; addColumn tableName=OFFLINE_USER_SESSION; update tableName=OF...		\N	3.5.4	\N	\N	7772459249
1.6.1	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 12:21:00.317123	17	EXECUTED	7:d41d8cd98f00b204e9800998ecf8427e	empty		\N	3.5.4	\N	\N	7772459249
1.7.0	bburke@redhat.com	META-INF/jpa-changelog-1.7.0.xml	2019-09-06 12:21:00.392497	18	EXECUTED	7:91ace540896df890cc00a0490ee52bbc	createTable tableName=KEYCLOAK_GROUP; createTable tableName=GROUP_ROLE_MAPPING; createTable tableName=GROUP_ATTRIBUTE; createTable tableName=USER_GROUP_MEMBERSHIP; createTable tableName=REALM_DEFAULT_GROUPS; addColumn tableName=IDENTITY_PROVIDER; ...		\N	3.5.4	\N	\N	7772459249
1.8.0	mposolda@redhat.com	META-INF/jpa-changelog-1.8.0.xml	2019-09-06 12:21:00.466059	19	EXECUTED	7:c31d1646dfa2618a9335c00e07f89f24	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	3.5.4	\N	\N	7772459249
1.8.0-2	keycloak	META-INF/jpa-changelog-1.8.0.xml	2019-09-06 12:21:00.470964	20	EXECUTED	7:df8bc21027a4f7cbbb01f6344e89ce07	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	3.5.4	\N	\N	7772459249
authz-3.4.0.CR1-resource-server-pk-change-part1	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 12:21:01.111463	45	EXECUTED	7:6a48ce645a3525488a90fbf76adf3bb3	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_RESOURCE; addColumn tableName=RESOURCE_SERVER_SCOPE		\N	3.5.4	\N	\N	7772459249
1.8.0	mposolda@redhat.com	META-INF/db2-jpa-changelog-1.8.0.xml	2019-09-06 12:21:00.473379	21	MARK_RAN	7:f987971fe6b37d963bc95fee2b27f8df	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	3.5.4	\N	\N	7772459249
1.8.0-2	keycloak	META-INF/db2-jpa-changelog-1.8.0.xml	2019-09-06 12:21:00.475908	22	MARK_RAN	7:df8bc21027a4f7cbbb01f6344e89ce07	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	3.5.4	\N	\N	7772459249
1.9.0	mposolda@redhat.com	META-INF/jpa-changelog-1.9.0.xml	2019-09-06 12:21:00.493857	23	EXECUTED	7:ed2dc7f799d19ac452cbcda56c929e47	update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=REALM; update tableName=REALM; customChange; dr...		\N	3.5.4	\N	\N	7772459249
1.9.1	keycloak	META-INF/jpa-changelog-1.9.1.xml	2019-09-06 12:21:00.49834	24	EXECUTED	7:80b5db88a5dda36ece5f235be8757615	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=PUBLIC_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	3.5.4	\N	\N	7772459249
1.9.1	keycloak	META-INF/db2-jpa-changelog-1.9.1.xml	2019-09-06 12:21:00.500546	25	MARK_RAN	7:1437310ed1305a9b93f8848f301726ce	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	3.5.4	\N	\N	7772459249
1.9.2	keycloak	META-INF/jpa-changelog-1.9.2.xml	2019-09-06 12:21:00.530146	26	EXECUTED	7:b82ffb34850fa0836be16deefc6a87c4	createIndex indexName=IDX_USER_EMAIL, tableName=USER_ENTITY; createIndex indexName=IDX_USER_ROLE_MAPPING, tableName=USER_ROLE_MAPPING; createIndex indexName=IDX_USER_GROUP_MAPPING, tableName=USER_GROUP_MEMBERSHIP; createIndex indexName=IDX_USER_CO...		\N	3.5.4	\N	\N	7772459249
authz-2.0.0	psilva@redhat.com	META-INF/jpa-changelog-authz-2.0.0.xml	2019-09-06 12:21:00.652324	27	EXECUTED	7:9cc98082921330d8d9266decdd4bd658	createTable tableName=RESOURCE_SERVER; addPrimaryKey constraintName=CONSTRAINT_FARS, tableName=RESOURCE_SERVER; addUniqueConstraint constraintName=UK_AU8TT6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER; createTable tableName=RESOURCE_SERVER_RESOU...		\N	3.5.4	\N	\N	7772459249
authz-2.5.1	psilva@redhat.com	META-INF/jpa-changelog-authz-2.5.1.xml	2019-09-06 12:21:00.660889	28	EXECUTED	7:03d64aeed9cb52b969bd30a7ac0db57e	update tableName=RESOURCE_SERVER_POLICY		\N	3.5.4	\N	\N	7772459249
2.1.0-KEYCLOAK-5461	bburke@redhat.com	META-INF/jpa-changelog-2.1.0.xml	2019-09-06 12:21:00.76068	29	EXECUTED	7:f1f9fd8710399d725b780f463c6b21cd	createTable tableName=BROKER_LINK; createTable tableName=FED_USER_ATTRIBUTE; createTable tableName=FED_USER_CONSENT; createTable tableName=FED_USER_CONSENT_ROLE; createTable tableName=FED_USER_CONSENT_PROT_MAPPER; createTable tableName=FED_USER_CR...		\N	3.5.4	\N	\N	7772459249
2.2.0	bburke@redhat.com	META-INF/jpa-changelog-2.2.0.xml	2019-09-06 12:21:00.789545	30	EXECUTED	7:53188c3eb1107546e6f765835705b6c1	addColumn tableName=ADMIN_EVENT_ENTITY; createTable tableName=CREDENTIAL_ATTRIBUTE; createTable tableName=FED_CREDENTIAL_ATTRIBUTE; modifyDataType columnName=VALUE, tableName=CREDENTIAL; addForeignKeyConstraint baseTableName=FED_CREDENTIAL_ATTRIBU...		\N	3.5.4	\N	\N	7772459249
2.3.0	bburke@redhat.com	META-INF/jpa-changelog-2.3.0.xml	2019-09-06 12:21:00.822406	31	EXECUTED	7:d6e6f3bc57a0c5586737d1351725d4d4	createTable tableName=FEDERATED_USER; addPrimaryKey constraintName=CONSTR_FEDERATED_USER, tableName=FEDERATED_USER; dropDefaultValue columnName=TOTP, tableName=USER_ENTITY; dropColumn columnName=TOTP, tableName=USER_ENTITY; addColumn tableName=IDE...		\N	3.5.4	\N	\N	7772459249
2.4.0	bburke@redhat.com	META-INF/jpa-changelog-2.4.0.xml	2019-09-06 12:21:00.836016	32	EXECUTED	7:454d604fbd755d9df3fd9c6329043aa5	customChange		\N	3.5.4	\N	\N	7772459249
2.5.0	bburke@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 12:21:00.851178	33	EXECUTED	7:57e98a3077e29caf562f7dbf80c72600	customChange; modifyDataType columnName=USER_ID, tableName=OFFLINE_USER_SESSION		\N	3.5.4	\N	\N	7772459249
2.5.0-unicode-oracle	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 12:21:00.85692	34	MARK_RAN	7:e4c7e8f2256210aee71ddc42f538b57a	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	3.5.4	\N	\N	7772459249
2.5.0-unicode-other-dbs	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 12:21:00.907908	35	EXECUTED	7:09a43c97e49bc626460480aa1379b522	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	3.5.4	\N	\N	7772459249
2.5.0-duplicate-email-support	slawomir@dabek.name	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 12:21:00.929787	36	EXECUTED	7:26bfc7c74fefa9126f2ce702fb775553	addColumn tableName=REALM		\N	3.5.4	\N	\N	7772459249
2.5.0-unique-group-names	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 12:21:00.935214	37	EXECUTED	7:a161e2ae671a9020fff61e996a207377	addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	3.5.4	\N	\N	7772459249
2.5.1	bburke@redhat.com	META-INF/jpa-changelog-2.5.1.xml	2019-09-06 12:21:00.938754	38	EXECUTED	7:37fc1781855ac5388c494f1442b3f717	addColumn tableName=FED_USER_CONSENT		\N	3.5.4	\N	\N	7772459249
3.0.0	bburke@redhat.com	META-INF/jpa-changelog-3.0.0.xml	2019-09-06 12:21:00.949594	39	EXECUTED	7:13a27db0dae6049541136adad7261d27	addColumn tableName=IDENTITY_PROVIDER		\N	3.5.4	\N	\N	7772459249
3.2.0-fix	keycloak	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 12:21:00.951979	40	MARK_RAN	7:550300617e3b59e8af3a6294df8248a3	addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS		\N	3.5.4	\N	\N	7772459249
3.2.0-fix-with-keycloak-5416	keycloak	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 12:21:00.953986	41	MARK_RAN	7:e3a9482b8931481dc2772a5c07c44f17	dropIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS; addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS; createIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS		\N	3.5.4	\N	\N	7772459249
3.2.0-fix-offline-sessions	hmlnarik	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 12:21:00.958804	42	EXECUTED	7:72b07d85a2677cb257edb02b408f332d	customChange		\N	3.5.4	\N	\N	7772459249
3.2.0-fixed	keycloak	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 12:21:01.090933	43	EXECUTED	7:a72a7858967bd414835d19e04d880312	addColumn tableName=REALM; dropPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_PK2, tableName=OFFLINE_CLIENT_SESSION; dropColumn columnName=CLIENT_SESSION_ID, tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_P...		\N	3.5.4	\N	\N	7772459249
3.3.0	keycloak	META-INF/jpa-changelog-3.3.0.xml	2019-09-06 12:21:01.106904	44	EXECUTED	7:94edff7cf9ce179e7e85f0cd78a3cf2c	addColumn tableName=USER_ENTITY		\N	3.5.4	\N	\N	7772459249
authz-3.4.0.CR1-resource-server-pk-change-part2-KEYCLOAK-6095	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 12:21:01.115315	46	EXECUTED	7:e64b5dcea7db06077c6e57d3b9e5ca14	customChange		\N	3.5.4	\N	\N	7772459249
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 12:21:01.117149	47	MARK_RAN	7:fd8cf02498f8b1e72496a20afc75178c	dropIndex indexName=IDX_RES_SERV_POL_RES_SERV, tableName=RESOURCE_SERVER_POLICY; dropIndex indexName=IDX_RES_SRV_RES_RES_SRV, tableName=RESOURCE_SERVER_RESOURCE; dropIndex indexName=IDX_RES_SRV_SCOPE_RES_SRV, tableName=RESOURCE_SERVER_SCOPE		\N	3.5.4	\N	\N	7772459249
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed-nodropindex	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 12:21:01.148139	48	EXECUTED	7:542794f25aa2b1fbabb7e577d6646319	addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_POLICY; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_RESOURCE; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, ...		\N	3.5.4	\N	\N	7772459249
authn-3.4.0.CR1-refresh-token-max-reuse	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 12:21:01.163759	49	EXECUTED	7:edad604c882df12f74941dac3cc6d650	addColumn tableName=REALM		\N	3.5.4	\N	\N	7772459249
3.4.0	keycloak	META-INF/jpa-changelog-3.4.0.xml	2019-09-06 12:21:01.213821	50	EXECUTED	7:0f88b78b7b46480eb92690cbf5e44900	addPrimaryKey constraintName=CONSTRAINT_REALM_DEFAULT_ROLES, tableName=REALM_DEFAULT_ROLES; addPrimaryKey constraintName=CONSTRAINT_COMPOSITE_ROLE, tableName=COMPOSITE_ROLE; addPrimaryKey constraintName=CONSTR_REALM_DEFAULT_GROUPS, tableName=REALM...		\N	3.5.4	\N	\N	7772459249
3.4.0-KEYCLOAK-5230	hmlnarik@redhat.com	META-INF/jpa-changelog-3.4.0.xml	2019-09-06 12:21:01.244199	51	EXECUTED	7:d560e43982611d936457c327f872dd59	createIndex indexName=IDX_FU_ATTRIBUTE, tableName=FED_USER_ATTRIBUTE; createIndex indexName=IDX_FU_CONSENT, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CONSENT_RU, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CREDENTIAL, t...		\N	3.5.4	\N	\N	7772459249
3.4.1	psilva@redhat.com	META-INF/jpa-changelog-3.4.1.xml	2019-09-06 12:21:01.24791	52	EXECUTED	7:c155566c42b4d14ef07059ec3b3bbd8e	modifyDataType columnName=VALUE, tableName=CLIENT_ATTRIBUTES		\N	3.5.4	\N	\N	7772459249
3.4.2	keycloak	META-INF/jpa-changelog-3.4.2.xml	2019-09-06 12:21:01.250738	53	EXECUTED	7:b40376581f12d70f3c89ba8ddf5b7dea	update tableName=REALM		\N	3.5.4	\N	\N	7772459249
3.4.2-KEYCLOAK-5172	mkanis@redhat.com	META-INF/jpa-changelog-3.4.2.xml	2019-09-06 12:21:01.25333	54	EXECUTED	7:a1132cc395f7b95b3646146c2e38f168	update tableName=CLIENT		\N	3.5.4	\N	\N	7772459249
4.0.0-KEYCLOAK-6335	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 12:21:01.259672	55	EXECUTED	7:d8dc5d89c789105cfa7ca0e82cba60af	createTable tableName=CLIENT_AUTH_FLOW_BINDINGS; addPrimaryKey constraintName=C_CLI_FLOW_BIND, tableName=CLIENT_AUTH_FLOW_BINDINGS		\N	3.5.4	\N	\N	7772459249
4.0.0-CLEANUP-UNUSED-TABLE	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 12:21:01.26449	56	EXECUTED	7:7822e0165097182e8f653c35517656a3	dropTable tableName=CLIENT_IDENTITY_PROV_MAPPING		\N	3.5.4	\N	\N	7772459249
4.0.0-KEYCLOAK-6228	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 12:21:01.298141	57	EXECUTED	7:c6538c29b9c9a08f9e9ea2de5c2b6375	dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; dropNotNullConstraint columnName=CLIENT_ID, tableName=USER_CONSENT; addColumn tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHO...		\N	3.5.4	\N	\N	7772459249
4.0.0-KEYCLOAK-5579-fixed	mposolda@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 12:21:01.402763	58	EXECUTED	7:6d4893e36de22369cf73bcb051ded875	dropForeignKeyConstraint baseTableName=CLIENT_TEMPLATE_ATTRIBUTES, constraintName=FK_CL_TEMPL_ATTR_TEMPL; renameTable newTableName=CLIENT_SCOPE_ATTRIBUTES, oldTableName=CLIENT_TEMPLATE_ATTRIBUTES; renameColumn newColumnName=SCOPE_ID, oldColumnName...		\N	3.5.4	\N	\N	7772459249
authz-4.0.0.CR1	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.CR1.xml	2019-09-06 12:21:01.460375	59	EXECUTED	7:57960fc0b0f0dd0563ea6f8b2e4a1707	createTable tableName=RESOURCE_SERVER_PERM_TICKET; addPrimaryKey constraintName=CONSTRAINT_FAPMT, tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRHO213XCX4WNKOG82SSPMT...		\N	3.5.4	\N	\N	7772459249
authz-4.0.0.Beta3	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.Beta3.xml	2019-09-06 12:21:01.472526	60	EXECUTED	7:2b4b8bff39944c7097977cc18dbceb3b	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRPO2128CX4WNKOG82SSRFY, referencedTableName=RESOURCE_SERVER_POLICY		\N	3.5.4	\N	\N	7772459249
authz-4.2.0.Final	mhajas@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2019-09-06 12:21:01.491975	61	EXECUTED	7:2aa42a964c59cd5b8ca9822340ba33a8	createTable tableName=RESOURCE_URIS; addForeignKeyConstraint baseTableName=RESOURCE_URIS, constraintName=FK_RESOURCE_SERVER_URIS, referencedTableName=RESOURCE_SERVER_RESOURCE; customChange; dropColumn columnName=URI, tableName=RESOURCE_SERVER_RESO...		\N	3.5.4	\N	\N	7772459249
4.2.0-KEYCLOAK-6313	wadahiro@gmail.com	META-INF/jpa-changelog-4.2.0.xml	2019-09-06 12:21:01.499896	62	EXECUTED	7:14d407c35bc4fe1976867756bcea0c36	addColumn tableName=REQUIRED_ACTION_PROVIDER		\N	3.5.4	\N	\N	7772459249
4.3.0-KEYCLOAK-7984	wadahiro@gmail.com	META-INF/jpa-changelog-4.3.0.xml	2019-09-06 12:21:01.505739	63	EXECUTED	7:241a8030c748c8548e346adee548fa93	update tableName=REQUIRED_ACTION_PROVIDER		\N	3.5.4	\N	\N	7772459249
4.6.0-KEYCLOAK-7950	psilva@redhat.com	META-INF/jpa-changelog-4.6.0.xml	2019-09-06 12:21:01.510532	64	EXECUTED	7:7d3182f65a34fcc61e8d23def037dc3f	update tableName=RESOURCE_SERVER_RESOURCE		\N	3.5.4	\N	\N	7772459249
4.6.0-KEYCLOAK-8377	keycloak	META-INF/jpa-changelog-4.6.0.xml	2019-09-06 12:21:01.527198	65	EXECUTED	7:b30039e00a0b9715d430d1b0636728fa	createTable tableName=ROLE_ATTRIBUTE; addPrimaryKey constraintName=CONSTRAINT_ROLE_ATTRIBUTE_PK, tableName=ROLE_ATTRIBUTE; addForeignKeyConstraint baseTableName=ROLE_ATTRIBUTE, constraintName=FK_ROLE_ATTRIBUTE_ID, referencedTableName=KEYCLOAK_ROLE...		\N	3.5.4	\N	\N	7772459249
4.6.0-KEYCLOAK-8555	gideonray@gmail.com	META-INF/jpa-changelog-4.6.0.xml	2019-09-06 12:21:01.533079	66	EXECUTED	7:3797315ca61d531780f8e6f82f258159	createIndex indexName=IDX_COMPONENT_PROVIDER_TYPE, tableName=COMPONENT		\N	3.5.4	\N	\N	7772459249
4.7.0-KEYCLOAK-1267	sguilhen@redhat.com	META-INF/jpa-changelog-4.7.0.xml	2019-09-06 12:21:01.5627	67	EXECUTED	7:c7aa4c8d9573500c2d347c1941ff0301	addColumn tableName=REALM		\N	3.5.4	\N	\N	7772459249
4.7.0-KEYCLOAK-7275	keycloak	META-INF/jpa-changelog-4.7.0.xml	2019-09-06 12:21:01.579523	68	EXECUTED	7:b207faee394fc074a442ecd42185a5dd	renameColumn newColumnName=CREATED_ON, oldColumnName=LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION; addNotNullConstraint columnName=CREATED_ON, tableName=OFFLINE_USER_SESSION; addColumn tableName=OFFLINE_USER_SESSION; customChange; createIn...		\N	3.5.4	\N	\N	7772459249
4.8.0-KEYCLOAK-8835	sguilhen@redhat.com	META-INF/jpa-changelog-4.8.0.xml	2019-09-06 12:21:01.584617	69	EXECUTED	7:ab9a9762faaba4ddfa35514b212c4922	addNotNullConstraint columnName=SSO_MAX_LIFESPAN_REMEMBER_ME, tableName=REALM; addNotNullConstraint columnName=SSO_IDLE_TIMEOUT_REMEMBER_ME, tableName=REALM		\N	3.5.4	\N	\N	7772459249
\.


--
-- Data for Name: databasechangeloglock; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.databasechangeloglock (id, locked, lockgranted, lockedby) FROM stdin;
1	f	\N	\N
\.


--
-- Data for Name: default_client_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.default_client_scope (realm_id, scope_id, default_scope) FROM stdin;
master	671a5049-fab0-4a2c-9fe0-a59120aaf323	f
master	42a3deed-4e91-484a-a75c-b63cff67e67a	t
master	26cf9780-ae5f-4740-83f6-120a23a2bc94	t
master	0c316958-1718-4d46-a024-d1fad4693feb	t
master	e20c2763-240b-443e-a71d-1ebccaf79387	f
master	6dc72d0e-f25a-4962-8040-351ace0aa19a	f
master	06b0e688-b570-4424-ac5e-8224791da759	t
master	8888ca84-252e-41ec-929e-8776aeced16b	t
master	3884a85d-5aed-4209-90e1-87b4978f9ef5	f
\.


--
-- Data for Name: event_entity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.event_entity (id, client_id, details_json, error, ip_address, realm_id, session_id, event_time, type, user_id) FROM stdin;
\.


--
-- Data for Name: fed_credential_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_credential_attribute (id, credential_id, name, value) FROM stdin;
\.


--
-- Data for Name: fed_user_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_attribute (id, name, user_id, realm_id, storage_provider_id, value) FROM stdin;
\.


--
-- Data for Name: fed_user_consent; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_consent (id, client_id, user_id, realm_id, storage_provider_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: fed_user_consent_cl_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_consent_cl_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: fed_user_credential; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_credential (id, device, hash_iterations, salt, type, value, created_date, counter, digits, period, algorithm, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_group_membership; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_group_membership (group_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_required_action; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_required_action (required_action, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_role_mapping (role_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: federated_identity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.federated_identity (identity_provider, realm_id, federated_user_id, federated_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: federated_user; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.federated_user (id, storage_provider_id, realm_id) FROM stdin;
\.


--
-- Data for Name: group_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.group_attribute (id, name, value, group_id) FROM stdin;
\.


--
-- Data for Name: group_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.group_role_mapping (role_id, group_id) FROM stdin;
\.


--
-- Data for Name: identity_provider; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.identity_provider (internal_id, enabled, provider_alias, provider_id, store_token, authenticate_by_default, realm_id, add_token_role, trust_email, first_broker_login_flow_id, post_broker_login_flow_id, provider_display_name, link_only) FROM stdin;
\.


--
-- Data for Name: identity_provider_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.identity_provider_config (identity_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: identity_provider_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.identity_provider_mapper (id, name, idp_alias, idp_mapper_name, realm_id) FROM stdin;
\.


--
-- Data for Name: idp_mapper_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.idp_mapper_config (idp_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: keycloak_group; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.keycloak_group (id, name, parent_group, realm_id) FROM stdin;
114383b2-d005-4e24-977c-c5f177a3ac39	can-do-that-flaminem	\N	master
4815128e-b4f2-4993-8fda-06ae42c2e2da	can-do-this-flaminem	\N	master
\.


--
-- Data for Name: keycloak_role; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.keycloak_role (id, client_realm_constraint, client_role, description, name, realm_id, client, realm) FROM stdin;
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	master	f	${role_admin}	admin	master	\N	master
02d4d60d-3d16-4ee0-b6da-b3b037edea09	master	f	${role_create-realm}	create-realm	master	\N	master
f7884cf5-2c68-4543-aa55-5533b96c4345	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_create-client}	create-client	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
96e13568-bf75-4449-abae-c36acfd1f05b	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_view-realm}	view-realm	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
e2154b31-49cc-4637-bb9b-e6b07aac06cb	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_view-users}	view-users	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
b6cdf90e-2364-4b39-9c29-e4108f18f567	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_view-clients}	view-clients	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
569d276b-64ce-474f-9b0b-2ee46983ba1e	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_view-events}	view-events	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
309a3441-f553-49f8-a8f8-4c8b179b9e48	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_view-identity-providers}	view-identity-providers	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
f0350b21-7be8-4e12-951a-841a39a05697	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_view-authorization}	view-authorization	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
a5eb862d-9a71-442a-bbee-78181eab52b9	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_manage-realm}	manage-realm	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
767bf792-99d8-412b-820c-8bfab54c0ca8	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_manage-users}	manage-users	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
6dbe0e1c-dcec-4e01-9c28-aa742be30039	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_manage-clients}	manage-clients	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
f1782dbc-0ac5-47d1-9cb7-c69a7aa578a4	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_manage-events}	manage-events	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
75aa5b45-22dc-439b-b4c6-fa8aef64d2d1	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_manage-identity-providers}	manage-identity-providers	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
1100d31c-1130-485e-9e56-83779cf139b5	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_manage-authorization}	manage-authorization	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
c8848376-9f44-451f-b00a-5e659e91cf84	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_query-users}	query-users	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
d5129a14-e8ec-444d-8217-587e12692839	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_query-clients}	query-clients	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
b4381f40-4573-445a-95ef-1778d7e1fd88	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_query-realms}	query-realms	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
d6d25d90-c45d-4ce7-bae7-b71c27603992	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_query-groups}	query-groups	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
a18b0b30-b25d-41f1-8ad2-05a076abd1ec	acbbd3df-4682-4d8e-ba24-f32cab9df9cb	t	${role_view-profile}	view-profile	master	acbbd3df-4682-4d8e-ba24-f32cab9df9cb	\N
ccbb3f8b-7022-41cc-be8d-b78c487bcf55	acbbd3df-4682-4d8e-ba24-f32cab9df9cb	t	${role_manage-account}	manage-account	master	acbbd3df-4682-4d8e-ba24-f32cab9df9cb	\N
df922ee4-c20b-4441-8fde-8fe7c8573f63	acbbd3df-4682-4d8e-ba24-f32cab9df9cb	t	${role_manage-account-links}	manage-account-links	master	acbbd3df-4682-4d8e-ba24-f32cab9df9cb	\N
eb6769a3-6411-442f-9173-c373dff19fb3	bfdd8008-8b63-4961-b9b9-09e28839bf14	t	${role_read-token}	read-token	master	bfdd8008-8b63-4961-b9b9-09e28839bf14	\N
af439cfb-c438-4fb6-b884-2e5ae1fe1721	8660773b-92db-46c8-a9ef-93ecc53f24d8	t	${role_impersonation}	impersonation	master	8660773b-92db-46c8-a9ef-93ecc53f24d8	\N
cec463df-65c7-454b-bddd-467f0eb38cc5	master	f	${role_offline-access}	offline_access	master	\N	master
585d8556-a38a-48ff-a00d-81bed28618bc	master	f	${role_uma_authorization}	uma_authorization	master	\N	master
95c788ae-a160-49fb-abf6-de0c591bfd74	master	f		external-keycloak-role	master	\N	master
\.


--
-- Data for Name: migration_model; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.migration_model (id, version) FROM stdin;
SINGLETON	4.6.0
\.


--
-- Data for Name: offline_client_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.offline_client_session (user_session_id, client_id, offline_flag, "timestamp", data, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: offline_user_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.offline_user_session (user_session_id, user_id, realm_id, created_on, offline_flag, data, last_session_refresh) FROM stdin;
\.


--
-- Data for Name: policy_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.policy_config (policy_id, name, value) FROM stdin;
\.


--
-- Data for Name: protocol_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.protocol_mapper (id, name, protocol, protocol_mapper_name, client_id, client_scope_id) FROM stdin;
9b919465-f673-4317-a9a0-6b8dda55d097	locale	openid-connect	oidc-usermodel-attribute-mapper	0bce9c9c-c9b8-457f-ba02-efced1af0df6	\N
9ae4669e-d83f-47e0-917f-0de97254cbb7	role list	saml	saml-role-list-mapper	\N	42a3deed-4e91-484a-a75c-b63cff67e67a
c406b314-e908-4d2e-bbff-f2e0999a4019	full name	openid-connect	oidc-full-name-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
712ecd83-6ea1-4958-800e-c5fa7c8974cf	family name	openid-connect	oidc-usermodel-property-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
790be6c4-5c4e-46ac-a216-8594307d4631	given name	openid-connect	oidc-usermodel-property-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
2a223c75-8644-4646-a108-dea9cd14b23d	middle name	openid-connect	oidc-usermodel-attribute-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
f164e844-6233-49bf-bda0-7a5217f9f0b5	nickname	openid-connect	oidc-usermodel-attribute-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
684711e2-ca18-47c1-9480-cde8d38752d2	username	openid-connect	oidc-usermodel-property-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
2908e6a5-9361-45e1-8bb6-e6d99bd3fae8	profile	openid-connect	oidc-usermodel-attribute-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
f94f1853-6759-4b7a-b431-8363f9ba09ae	picture	openid-connect	oidc-usermodel-attribute-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
67e1e062-dfaf-4dc7-8e09-5bc3cd97f879	website	openid-connect	oidc-usermodel-attribute-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
b65aac9d-122f-4239-907a-aafe8616f764	gender	openid-connect	oidc-usermodel-attribute-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
036de780-999a-484a-8ea4-45369ca4cb60	birthdate	openid-connect	oidc-usermodel-attribute-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
f3ba261e-d718-40db-9a68-05a231514118	zoneinfo	openid-connect	oidc-usermodel-attribute-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
fa8f12cc-7bc8-4c26-907d-0bfab7f31c50	locale	openid-connect	oidc-usermodel-attribute-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
e452d52a-2788-4b46-b865-568d46109526	updated at	openid-connect	oidc-usermodel-attribute-mapper	\N	26cf9780-ae5f-4740-83f6-120a23a2bc94
07fb350f-c23b-4cbc-953f-f309ffe3d3f1	email	openid-connect	oidc-usermodel-property-mapper	\N	0c316958-1718-4d46-a024-d1fad4693feb
5b5694b4-be16-41f0-818b-a24ff9f417ee	email verified	openid-connect	oidc-usermodel-property-mapper	\N	0c316958-1718-4d46-a024-d1fad4693feb
a7ec06b7-5e95-4da0-b0e8-c2526652d876	address	openid-connect	oidc-address-mapper	\N	e20c2763-240b-443e-a71d-1ebccaf79387
5cdcee35-ab9c-4226-89c2-556f6e3d2e5e	phone number	openid-connect	oidc-usermodel-attribute-mapper	\N	6dc72d0e-f25a-4962-8040-351ace0aa19a
90958285-8611-42b8-b429-5f21ff402f08	phone number verified	openid-connect	oidc-usermodel-attribute-mapper	\N	6dc72d0e-f25a-4962-8040-351ace0aa19a
3281a47d-50a5-4971-a9db-a36736486809	realm roles	openid-connect	oidc-usermodel-realm-role-mapper	\N	06b0e688-b570-4424-ac5e-8224791da759
1af691ef-6fda-49e6-913b-c66e0434d6f4	client roles	openid-connect	oidc-usermodel-client-role-mapper	\N	06b0e688-b570-4424-ac5e-8224791da759
b54ed26e-291a-4a08-88ca-deece49543a0	audience resolve	openid-connect	oidc-audience-resolve-mapper	\N	06b0e688-b570-4424-ac5e-8224791da759
16475bc7-98f0-4568-b481-419427f1c17c	allowed web origins	openid-connect	oidc-allowed-origins-mapper	\N	8888ca84-252e-41ec-929e-8776aeced16b
707dc54d-ed57-4807-9c05-02f26c1d81c1	upn	openid-connect	oidc-usermodel-property-mapper	\N	3884a85d-5aed-4209-90e1-87b4978f9ef5
9743b95c-14d8-4514-86e4-c2fbe9178f4e	groups	openid-connect	oidc-usermodel-realm-role-mapper	\N	3884a85d-5aed-4209-90e1-87b4978f9ef5
57c87fec-f7f3-473f-b232-d99da585df19	groups	openid-connect	oidc-group-membership-mapper	d5a33898-5c96-4b96-8f29-c1bec691def4	\N
\.


--
-- Data for Name: protocol_mapper_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.protocol_mapper_config (protocol_mapper_id, value, name) FROM stdin;
9b919465-f673-4317-a9a0-6b8dda55d097	true	userinfo.token.claim
9b919465-f673-4317-a9a0-6b8dda55d097	locale	user.attribute
9b919465-f673-4317-a9a0-6b8dda55d097	true	id.token.claim
9b919465-f673-4317-a9a0-6b8dda55d097	true	access.token.claim
9b919465-f673-4317-a9a0-6b8dda55d097	locale	claim.name
9b919465-f673-4317-a9a0-6b8dda55d097	String	jsonType.label
9ae4669e-d83f-47e0-917f-0de97254cbb7	false	single
9ae4669e-d83f-47e0-917f-0de97254cbb7	Basic	attribute.nameformat
9ae4669e-d83f-47e0-917f-0de97254cbb7	Role	attribute.name
c406b314-e908-4d2e-bbff-f2e0999a4019	true	userinfo.token.claim
c406b314-e908-4d2e-bbff-f2e0999a4019	true	id.token.claim
c406b314-e908-4d2e-bbff-f2e0999a4019	true	access.token.claim
712ecd83-6ea1-4958-800e-c5fa7c8974cf	true	userinfo.token.claim
712ecd83-6ea1-4958-800e-c5fa7c8974cf	lastName	user.attribute
712ecd83-6ea1-4958-800e-c5fa7c8974cf	true	id.token.claim
712ecd83-6ea1-4958-800e-c5fa7c8974cf	true	access.token.claim
712ecd83-6ea1-4958-800e-c5fa7c8974cf	family_name	claim.name
712ecd83-6ea1-4958-800e-c5fa7c8974cf	String	jsonType.label
790be6c4-5c4e-46ac-a216-8594307d4631	true	userinfo.token.claim
790be6c4-5c4e-46ac-a216-8594307d4631	firstName	user.attribute
790be6c4-5c4e-46ac-a216-8594307d4631	true	id.token.claim
790be6c4-5c4e-46ac-a216-8594307d4631	true	access.token.claim
790be6c4-5c4e-46ac-a216-8594307d4631	given_name	claim.name
790be6c4-5c4e-46ac-a216-8594307d4631	String	jsonType.label
2a223c75-8644-4646-a108-dea9cd14b23d	true	userinfo.token.claim
2a223c75-8644-4646-a108-dea9cd14b23d	middleName	user.attribute
2a223c75-8644-4646-a108-dea9cd14b23d	true	id.token.claim
2a223c75-8644-4646-a108-dea9cd14b23d	true	access.token.claim
2a223c75-8644-4646-a108-dea9cd14b23d	middle_name	claim.name
2a223c75-8644-4646-a108-dea9cd14b23d	String	jsonType.label
f164e844-6233-49bf-bda0-7a5217f9f0b5	true	userinfo.token.claim
f164e844-6233-49bf-bda0-7a5217f9f0b5	nickname	user.attribute
f164e844-6233-49bf-bda0-7a5217f9f0b5	true	id.token.claim
f164e844-6233-49bf-bda0-7a5217f9f0b5	true	access.token.claim
f164e844-6233-49bf-bda0-7a5217f9f0b5	nickname	claim.name
f164e844-6233-49bf-bda0-7a5217f9f0b5	String	jsonType.label
684711e2-ca18-47c1-9480-cde8d38752d2	true	userinfo.token.claim
684711e2-ca18-47c1-9480-cde8d38752d2	username	user.attribute
684711e2-ca18-47c1-9480-cde8d38752d2	true	id.token.claim
684711e2-ca18-47c1-9480-cde8d38752d2	true	access.token.claim
684711e2-ca18-47c1-9480-cde8d38752d2	preferred_username	claim.name
684711e2-ca18-47c1-9480-cde8d38752d2	String	jsonType.label
2908e6a5-9361-45e1-8bb6-e6d99bd3fae8	true	userinfo.token.claim
2908e6a5-9361-45e1-8bb6-e6d99bd3fae8	profile	user.attribute
2908e6a5-9361-45e1-8bb6-e6d99bd3fae8	true	id.token.claim
2908e6a5-9361-45e1-8bb6-e6d99bd3fae8	true	access.token.claim
2908e6a5-9361-45e1-8bb6-e6d99bd3fae8	profile	claim.name
2908e6a5-9361-45e1-8bb6-e6d99bd3fae8	String	jsonType.label
f94f1853-6759-4b7a-b431-8363f9ba09ae	true	userinfo.token.claim
f94f1853-6759-4b7a-b431-8363f9ba09ae	picture	user.attribute
f94f1853-6759-4b7a-b431-8363f9ba09ae	true	id.token.claim
f94f1853-6759-4b7a-b431-8363f9ba09ae	true	access.token.claim
f94f1853-6759-4b7a-b431-8363f9ba09ae	picture	claim.name
f94f1853-6759-4b7a-b431-8363f9ba09ae	String	jsonType.label
67e1e062-dfaf-4dc7-8e09-5bc3cd97f879	true	userinfo.token.claim
67e1e062-dfaf-4dc7-8e09-5bc3cd97f879	website	user.attribute
67e1e062-dfaf-4dc7-8e09-5bc3cd97f879	true	id.token.claim
67e1e062-dfaf-4dc7-8e09-5bc3cd97f879	true	access.token.claim
67e1e062-dfaf-4dc7-8e09-5bc3cd97f879	website	claim.name
67e1e062-dfaf-4dc7-8e09-5bc3cd97f879	String	jsonType.label
b65aac9d-122f-4239-907a-aafe8616f764	true	userinfo.token.claim
b65aac9d-122f-4239-907a-aafe8616f764	gender	user.attribute
b65aac9d-122f-4239-907a-aafe8616f764	true	id.token.claim
b65aac9d-122f-4239-907a-aafe8616f764	true	access.token.claim
b65aac9d-122f-4239-907a-aafe8616f764	gender	claim.name
b65aac9d-122f-4239-907a-aafe8616f764	String	jsonType.label
036de780-999a-484a-8ea4-45369ca4cb60	true	userinfo.token.claim
036de780-999a-484a-8ea4-45369ca4cb60	birthdate	user.attribute
036de780-999a-484a-8ea4-45369ca4cb60	true	id.token.claim
036de780-999a-484a-8ea4-45369ca4cb60	true	access.token.claim
036de780-999a-484a-8ea4-45369ca4cb60	birthdate	claim.name
036de780-999a-484a-8ea4-45369ca4cb60	String	jsonType.label
f3ba261e-d718-40db-9a68-05a231514118	true	userinfo.token.claim
f3ba261e-d718-40db-9a68-05a231514118	zoneinfo	user.attribute
f3ba261e-d718-40db-9a68-05a231514118	true	id.token.claim
f3ba261e-d718-40db-9a68-05a231514118	true	access.token.claim
f3ba261e-d718-40db-9a68-05a231514118	zoneinfo	claim.name
f3ba261e-d718-40db-9a68-05a231514118	String	jsonType.label
fa8f12cc-7bc8-4c26-907d-0bfab7f31c50	true	userinfo.token.claim
fa8f12cc-7bc8-4c26-907d-0bfab7f31c50	locale	user.attribute
fa8f12cc-7bc8-4c26-907d-0bfab7f31c50	true	id.token.claim
fa8f12cc-7bc8-4c26-907d-0bfab7f31c50	true	access.token.claim
fa8f12cc-7bc8-4c26-907d-0bfab7f31c50	locale	claim.name
fa8f12cc-7bc8-4c26-907d-0bfab7f31c50	String	jsonType.label
e452d52a-2788-4b46-b865-568d46109526	true	userinfo.token.claim
e452d52a-2788-4b46-b865-568d46109526	updatedAt	user.attribute
e452d52a-2788-4b46-b865-568d46109526	true	id.token.claim
e452d52a-2788-4b46-b865-568d46109526	true	access.token.claim
e452d52a-2788-4b46-b865-568d46109526	updated_at	claim.name
e452d52a-2788-4b46-b865-568d46109526	String	jsonType.label
07fb350f-c23b-4cbc-953f-f309ffe3d3f1	true	userinfo.token.claim
07fb350f-c23b-4cbc-953f-f309ffe3d3f1	email	user.attribute
07fb350f-c23b-4cbc-953f-f309ffe3d3f1	true	id.token.claim
07fb350f-c23b-4cbc-953f-f309ffe3d3f1	true	access.token.claim
07fb350f-c23b-4cbc-953f-f309ffe3d3f1	email	claim.name
07fb350f-c23b-4cbc-953f-f309ffe3d3f1	String	jsonType.label
5b5694b4-be16-41f0-818b-a24ff9f417ee	true	userinfo.token.claim
5b5694b4-be16-41f0-818b-a24ff9f417ee	emailVerified	user.attribute
5b5694b4-be16-41f0-818b-a24ff9f417ee	true	id.token.claim
5b5694b4-be16-41f0-818b-a24ff9f417ee	true	access.token.claim
5b5694b4-be16-41f0-818b-a24ff9f417ee	email_verified	claim.name
5b5694b4-be16-41f0-818b-a24ff9f417ee	boolean	jsonType.label
a7ec06b7-5e95-4da0-b0e8-c2526652d876	formatted	user.attribute.formatted
a7ec06b7-5e95-4da0-b0e8-c2526652d876	country	user.attribute.country
a7ec06b7-5e95-4da0-b0e8-c2526652d876	postal_code	user.attribute.postal_code
a7ec06b7-5e95-4da0-b0e8-c2526652d876	true	userinfo.token.claim
a7ec06b7-5e95-4da0-b0e8-c2526652d876	street	user.attribute.street
a7ec06b7-5e95-4da0-b0e8-c2526652d876	true	id.token.claim
a7ec06b7-5e95-4da0-b0e8-c2526652d876	region	user.attribute.region
a7ec06b7-5e95-4da0-b0e8-c2526652d876	true	access.token.claim
a7ec06b7-5e95-4da0-b0e8-c2526652d876	locality	user.attribute.locality
5cdcee35-ab9c-4226-89c2-556f6e3d2e5e	true	userinfo.token.claim
5cdcee35-ab9c-4226-89c2-556f6e3d2e5e	phoneNumber	user.attribute
5cdcee35-ab9c-4226-89c2-556f6e3d2e5e	true	id.token.claim
5cdcee35-ab9c-4226-89c2-556f6e3d2e5e	true	access.token.claim
5cdcee35-ab9c-4226-89c2-556f6e3d2e5e	phone_number	claim.name
5cdcee35-ab9c-4226-89c2-556f6e3d2e5e	String	jsonType.label
90958285-8611-42b8-b429-5f21ff402f08	true	userinfo.token.claim
90958285-8611-42b8-b429-5f21ff402f08	phoneNumberVerified	user.attribute
90958285-8611-42b8-b429-5f21ff402f08	true	id.token.claim
90958285-8611-42b8-b429-5f21ff402f08	true	access.token.claim
90958285-8611-42b8-b429-5f21ff402f08	phone_number_verified	claim.name
90958285-8611-42b8-b429-5f21ff402f08	boolean	jsonType.label
3281a47d-50a5-4971-a9db-a36736486809	true	multivalued
3281a47d-50a5-4971-a9db-a36736486809	foo	user.attribute
3281a47d-50a5-4971-a9db-a36736486809	true	access.token.claim
3281a47d-50a5-4971-a9db-a36736486809	realm_access.roles	claim.name
3281a47d-50a5-4971-a9db-a36736486809	String	jsonType.label
1af691ef-6fda-49e6-913b-c66e0434d6f4	true	multivalued
1af691ef-6fda-49e6-913b-c66e0434d6f4	foo	user.attribute
1af691ef-6fda-49e6-913b-c66e0434d6f4	true	access.token.claim
1af691ef-6fda-49e6-913b-c66e0434d6f4	resource_access.${client_id}.roles	claim.name
1af691ef-6fda-49e6-913b-c66e0434d6f4	String	jsonType.label
707dc54d-ed57-4807-9c05-02f26c1d81c1	true	userinfo.token.claim
707dc54d-ed57-4807-9c05-02f26c1d81c1	username	user.attribute
707dc54d-ed57-4807-9c05-02f26c1d81c1	true	id.token.claim
707dc54d-ed57-4807-9c05-02f26c1d81c1	true	access.token.claim
707dc54d-ed57-4807-9c05-02f26c1d81c1	upn	claim.name
707dc54d-ed57-4807-9c05-02f26c1d81c1	String	jsonType.label
9743b95c-14d8-4514-86e4-c2fbe9178f4e	true	multivalued
9743b95c-14d8-4514-86e4-c2fbe9178f4e	foo	user.attribute
9743b95c-14d8-4514-86e4-c2fbe9178f4e	true	id.token.claim
9743b95c-14d8-4514-86e4-c2fbe9178f4e	true	access.token.claim
9743b95c-14d8-4514-86e4-c2fbe9178f4e	groups	claim.name
9743b95c-14d8-4514-86e4-c2fbe9178f4e	String	jsonType.label
57c87fec-f7f3-473f-b232-d99da585df19	false	full.path
57c87fec-f7f3-473f-b232-d99da585df19	true	id.token.claim
57c87fec-f7f3-473f-b232-d99da585df19	true	access.token.claim
57c87fec-f7f3-473f-b232-d99da585df19	groups	claim.name
57c87fec-f7f3-473f-b232-d99da585df19	true	userinfo.token.claim
\.


--
-- Data for Name: realm; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm (id, access_code_lifespan, user_action_lifespan, access_token_lifespan, account_theme, admin_theme, email_theme, enabled, events_enabled, events_expiration, login_theme, name, not_before, password_policy, registration_allowed, remember_me, reset_password_allowed, social, ssl_required, sso_idle_timeout, sso_max_lifespan, update_profile_on_soc_login, verify_email, master_admin_client, login_lifespan, internationalization_enabled, default_locale, reg_email_as_username, admin_events_enabled, admin_events_details_enabled, edit_username_allowed, otp_policy_counter, otp_policy_window, otp_policy_period, otp_policy_digits, otp_policy_alg, otp_policy_type, browser_flow, registration_flow, direct_grant_flow, reset_credentials_flow, client_auth_flow, offline_session_idle_timeout, revoke_refresh_token, access_token_life_implicit, login_with_email_allowed, duplicate_emails_allowed, docker_auth_flow, refresh_token_max_reuse, allow_user_managed_access, sso_max_lifespan_remember_me, sso_idle_timeout_remember_me) FROM stdin;
master	60	300	60	\N	\N	\N	t	f	0	\N	master	0	\N	f	f	f	f	EXTERNAL	1800	36000	f	f	8660773b-92db-46c8-a9ef-93ecc53f24d8	1800	f	\N	f	f	f	f	0	1	30	6	HmacSHA1	totp	5846cdc0-2f0f-4eba-b066-51ee5932bb52	f9c125ed-5473-494f-8840-0dea1559a4db	d7e087bf-6711-4e74-b170-9138ee76617c	c83d244b-a57c-4939-90cf-95b7f38006b9	4074ff48-6dc2-4e39-b15c-97bbc4bad36a	2592000	f	900	t	f	20644fe1-70a0-4f0e-a2ab-032bcb61741c	0	f	0	0
\.


--
-- Data for Name: realm_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_attribute (name, value, realm_id) FROM stdin;
_browser_header.contentSecurityPolicyReportOnly		master
_browser_header.xContentTypeOptions	nosniff	master
_browser_header.xRobotsTag	none	master
_browser_header.xFrameOptions	SAMEORIGIN	master
_browser_header.contentSecurityPolicy	frame-src 'self'; frame-ancestors 'self'; object-src 'none';	master
_browser_header.xXSSProtection	1; mode=block	master
_browser_header.strictTransportSecurity	max-age=31536000; includeSubDomains	master
bruteForceProtected	false	master
permanentLockout	false	master
maxFailureWaitSeconds	900	master
minimumQuickLoginWaitSeconds	60	master
waitIncrementSeconds	60	master
quickLoginCheckMilliSeconds	1000	master
maxDeltaTimeSeconds	43200	master
failureFactor	30	master
displayName	Keycloak	master
displayNameHtml	<div class="kc-logo-text"><span>Keycloak</span></div>	master
offlineSessionMaxLifespanEnabled	false	master
offlineSessionMaxLifespan	5184000	master
\.


--
-- Data for Name: realm_default_groups; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_default_groups (realm_id, group_id) FROM stdin;
\.


--
-- Data for Name: realm_default_roles; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_default_roles (realm_id, role_id) FROM stdin;
master	cec463df-65c7-454b-bddd-467f0eb38cc5
master	585d8556-a38a-48ff-a00d-81bed28618bc
\.


--
-- Data for Name: realm_enabled_event_types; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_enabled_event_types (realm_id, value) FROM stdin;
\.


--
-- Data for Name: realm_events_listeners; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_events_listeners (realm_id, value) FROM stdin;
master	jboss-logging
\.


--
-- Data for Name: realm_required_credential; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_required_credential (type, form_label, input, secret, realm_id) FROM stdin;
password	password	t	t	master
\.


--
-- Data for Name: realm_smtp_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_smtp_config (realm_id, value, name) FROM stdin;
\.


--
-- Data for Name: realm_supported_locales; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_supported_locales (realm_id, value) FROM stdin;
\.


--
-- Data for Name: redirect_uris; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.redirect_uris (client_id, value) FROM stdin;
acbbd3df-4682-4d8e-ba24-f32cab9df9cb	/auth/realms/master/account/*
0bce9c9c-c9b8-457f-ba02-efced1af0df6	/auth/admin/master/console/*
d5a33898-5c96-4b96-8f29-c1bec691def4	/broker/keycloak-oidc/*
\.


--
-- Data for Name: required_action_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.required_action_config (required_action_id, value, name) FROM stdin;
\.


--
-- Data for Name: required_action_provider; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.required_action_provider (id, alias, name, realm_id, enabled, default_action, provider_id, priority) FROM stdin;
13cf6a22-8054-4038-8b60-cad150be5d57	VERIFY_EMAIL	Verify Email	master	t	f	VERIFY_EMAIL	50
94856d30-aab6-4fd0-becd-d55f4e7aa51c	UPDATE_PROFILE	Update Profile	master	t	f	UPDATE_PROFILE	40
389652cf-7a7a-49ab-ac68-210e18e494db	CONFIGURE_TOTP	Configure OTP	master	t	f	CONFIGURE_TOTP	10
a787b019-0c31-4b02-ab8b-524113450922	UPDATE_PASSWORD	Update Password	master	t	f	UPDATE_PASSWORD	30
4275d316-699b-409b-ae36-951bbefd5833	terms_and_conditions	Terms and Conditions	master	f	f	terms_and_conditions	20
\.


--
-- Data for Name: resource_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_attribute (id, name, value, resource_id) FROM stdin;
\.


--
-- Data for Name: resource_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_policy (resource_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_scope (resource_id, scope_id) FROM stdin;
\.


--
-- Data for Name: resource_server; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server (id, allow_rs_remote_mgmt, policy_enforce_mode) FROM stdin;
\.


--
-- Data for Name: resource_server_perm_ticket; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_perm_ticket (id, owner, requester, created_timestamp, granted_timestamp, resource_id, scope_id, resource_server_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_server_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_policy (id, name, description, type, decision_strategy, logic, resource_server_id, owner) FROM stdin;
\.


--
-- Data for Name: resource_server_resource; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_resource (id, name, type, icon_uri, owner, resource_server_id, owner_managed_access, display_name) FROM stdin;
\.


--
-- Data for Name: resource_server_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_scope (id, name, icon_uri, resource_server_id, display_name) FROM stdin;
\.


--
-- Data for Name: resource_uris; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_uris (resource_id, value) FROM stdin;
\.


--
-- Data for Name: role_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.role_attribute (id, role_id, name, value) FROM stdin;
\.


--
-- Data for Name: scope_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.scope_mapping (client_id, role_id) FROM stdin;
\.


--
-- Data for Name: scope_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.scope_policy (scope_id, policy_id) FROM stdin;
\.


--
-- Data for Name: user_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_attribute (name, value, user_id, id) FROM stdin;
\.


--
-- Data for Name: user_consent; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_consent (id, client_id, user_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: user_consent_client_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_consent_client_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: user_entity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_entity (id, email, email_constraint, email_verified, enabled, federation_link, first_name, last_name, realm_id, username, created_timestamp, service_account_client_link, not_before) FROM stdin;
301d85b0-5cbf-426a-835c-9a497dec9e36	\N	53afadc1-87f9-46d9-b764-0d50fdbc2de2	f	t	\N	\N	\N	master	admin	1567772467720	\N	0
f51f95cd-9226-464a-a7ac-d04fd8a66333	frederic.bidon@yahoo.com	frederic.bidon@yahoo.com	t	t	\N	Frédéric	BIDON	master	frederic-keycloak	1568048927065	\N	0
\.


--
-- Data for Name: user_federation_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_config (user_federation_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_mapper (id, name, federation_provider_id, federation_mapper_type, realm_id) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_mapper_config (user_federation_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_provider; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_provider (id, changed_sync_period, display_name, full_sync_period, last_sync, priority, provider_name, realm_id) FROM stdin;
\.


--
-- Data for Name: user_group_membership; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_group_membership (group_id, user_id) FROM stdin;
114383b2-d005-4e24-977c-c5f177a3ac39	f51f95cd-9226-464a-a7ac-d04fd8a66333
4815128e-b4f2-4993-8fda-06ae42c2e2da	f51f95cd-9226-464a-a7ac-d04fd8a66333
\.


--
-- Data for Name: user_required_action; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_required_action (user_id, required_action) FROM stdin;
\.


--
-- Data for Name: user_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_role_mapping (role_id, user_id) FROM stdin;
ccbb3f8b-7022-41cc-be8d-b78c487bcf55	301d85b0-5cbf-426a-835c-9a497dec9e36
cec463df-65c7-454b-bddd-467f0eb38cc5	301d85b0-5cbf-426a-835c-9a497dec9e36
585d8556-a38a-48ff-a00d-81bed28618bc	301d85b0-5cbf-426a-835c-9a497dec9e36
a18b0b30-b25d-41f1-8ad2-05a076abd1ec	301d85b0-5cbf-426a-835c-9a497dec9e36
8d6058b7-e7cf-49f7-8971-8a5c0301e26e	301d85b0-5cbf-426a-835c-9a497dec9e36
ccbb3f8b-7022-41cc-be8d-b78c487bcf55	f51f95cd-9226-464a-a7ac-d04fd8a66333
cec463df-65c7-454b-bddd-467f0eb38cc5	f51f95cd-9226-464a-a7ac-d04fd8a66333
585d8556-a38a-48ff-a00d-81bed28618bc	f51f95cd-9226-464a-a7ac-d04fd8a66333
a18b0b30-b25d-41f1-8ad2-05a076abd1ec	f51f95cd-9226-464a-a7ac-d04fd8a66333
95c788ae-a160-49fb-abf6-de0c591bfd74	f51f95cd-9226-464a-a7ac-d04fd8a66333
\.


--
-- Data for Name: user_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_session (id, auth_method, ip_address, last_session_refresh, login_username, realm_id, remember_me, started, user_id, user_session_state, broker_session_id, broker_user_id) FROM stdin;
\.


--
-- Data for Name: user_session_note; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_session_note (user_session, name, value) FROM stdin;
\.


--
-- Data for Name: username_login_failure; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.username_login_failure (realm_id, username, failed_login_not_before, last_failure, last_ip_failure, num_failures) FROM stdin;
\.


--
-- Data for Name: web_origins; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.web_origins (client_id, value) FROM stdin;
\.


--
-- Name: username_login_failure CONSTRAINT_17-2; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.username_login_failure
    ADD CONSTRAINT "CONSTRAINT_17-2" PRIMARY KEY (realm_id, username);


--
-- Name: keycloak_role UK_J3RWUVD56ONTGSUHOGM184WW2-2; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT "UK_J3RWUVD56ONTGSUHOGM184WW2-2" UNIQUE (name, client_realm_constraint);


--
-- Name: client_auth_flow_bindings c_cli_flow_bind; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_auth_flow_bindings
    ADD CONSTRAINT c_cli_flow_bind PRIMARY KEY (client_id, binding_name);


--
-- Name: client_scope_client c_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT c_cli_scope_bind PRIMARY KEY (client_id, scope_id);


--
-- Name: client_initial_access cnstr_client_init_acc_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT cnstr_client_init_acc_pk PRIMARY KEY (id);


--
-- Name: realm_default_groups con_group_id_def_groups; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT con_group_id_def_groups UNIQUE (group_id);


--
-- Name: broker_link constr_broker_link_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.broker_link
    ADD CONSTRAINT constr_broker_link_pk PRIMARY KEY (identity_provider, user_id);


--
-- Name: client_user_session_note constr_cl_usr_ses_note; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_user_session_note
    ADD CONSTRAINT constr_cl_usr_ses_note PRIMARY KEY (client_session, name);


--
-- Name: client_default_roles constr_client_default_roles; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT constr_client_default_roles PRIMARY KEY (client_id, role_id);


--
-- Name: component_config constr_component_config_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT constr_component_config_pk PRIMARY KEY (id);


--
-- Name: component constr_component_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT constr_component_pk PRIMARY KEY (id);


--
-- Name: fed_user_required_action constr_fed_required_action; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_required_action
    ADD CONSTRAINT constr_fed_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: fed_user_attribute constr_fed_user_attr_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_attribute
    ADD CONSTRAINT constr_fed_user_attr_pk PRIMARY KEY (id);


--
-- Name: fed_user_consent constr_fed_user_consent_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_consent
    ADD CONSTRAINT constr_fed_user_consent_pk PRIMARY KEY (id);


--
-- Name: fed_user_credential constr_fed_user_cred_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_credential
    ADD CONSTRAINT constr_fed_user_cred_pk PRIMARY KEY (id);


--
-- Name: fed_user_group_membership constr_fed_user_group; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_group_membership
    ADD CONSTRAINT constr_fed_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: fed_user_role_mapping constr_fed_user_role; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_role_mapping
    ADD CONSTRAINT constr_fed_user_role PRIMARY KEY (role_id, user_id);


--
-- Name: federated_user constr_federated_user; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.federated_user
    ADD CONSTRAINT constr_federated_user PRIMARY KEY (id);


--
-- Name: realm_default_groups constr_realm_default_groups; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT constr_realm_default_groups PRIMARY KEY (realm_id, group_id);


--
-- Name: realm_enabled_event_types constr_realm_enabl_event_types; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT constr_realm_enabl_event_types PRIMARY KEY (realm_id, value);


--
-- Name: realm_events_listeners constr_realm_events_listeners; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT constr_realm_events_listeners PRIMARY KEY (realm_id, value);


--
-- Name: realm_supported_locales constr_realm_supported_locales; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT constr_realm_supported_locales PRIMARY KEY (realm_id, value);


--
-- Name: identity_provider constraint_2b; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT constraint_2b PRIMARY KEY (internal_id);


--
-- Name: client_attributes constraint_3c; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT constraint_3c PRIMARY KEY (client_id, name);


--
-- Name: event_entity constraint_4; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.event_entity
    ADD CONSTRAINT constraint_4 PRIMARY KEY (id);


--
-- Name: federated_identity constraint_40; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT constraint_40 PRIMARY KEY (identity_provider, user_id);


--
-- Name: realm constraint_4a; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT constraint_4a PRIMARY KEY (id);


--
-- Name: client_session_role constraint_5; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_role
    ADD CONSTRAINT constraint_5 PRIMARY KEY (client_session, role_id);


--
-- Name: user_session constraint_57; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_session
    ADD CONSTRAINT constraint_57 PRIMARY KEY (id);


--
-- Name: user_federation_provider constraint_5c; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT constraint_5c PRIMARY KEY (id);


--
-- Name: client_session_note constraint_5e; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_note
    ADD CONSTRAINT constraint_5e PRIMARY KEY (client_session, name);


--
-- Name: client constraint_7; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT constraint_7 PRIMARY KEY (id);


--
-- Name: client_session constraint_8; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session
    ADD CONSTRAINT constraint_8 PRIMARY KEY (id);


--
-- Name: scope_mapping constraint_81; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT constraint_81 PRIMARY KEY (client_id, role_id);


--
-- Name: client_node_registrations constraint_84; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT constraint_84 PRIMARY KEY (client_id, name);


--
-- Name: realm_attribute constraint_9; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT constraint_9 PRIMARY KEY (name, realm_id);


--
-- Name: realm_required_credential constraint_92; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT constraint_92 PRIMARY KEY (realm_id, type);


--
-- Name: keycloak_role constraint_a; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT constraint_a PRIMARY KEY (id);


--
-- Name: admin_event_entity constraint_admin_event_entity; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.admin_event_entity
    ADD CONSTRAINT constraint_admin_event_entity PRIMARY KEY (id);


--
-- Name: authenticator_config_entry constraint_auth_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authenticator_config_entry
    ADD CONSTRAINT constraint_auth_cfg_pk PRIMARY KEY (authenticator_id, name);


--
-- Name: authentication_execution constraint_auth_exec_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT constraint_auth_exec_pk PRIMARY KEY (id);


--
-- Name: authentication_flow constraint_auth_flow_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT constraint_auth_flow_pk PRIMARY KEY (id);


--
-- Name: authenticator_config constraint_auth_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT constraint_auth_pk PRIMARY KEY (id);


--
-- Name: client_session_auth_status constraint_auth_status_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_auth_status
    ADD CONSTRAINT constraint_auth_status_pk PRIMARY KEY (client_session, authenticator);


--
-- Name: user_role_mapping constraint_c; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT constraint_c PRIMARY KEY (role_id, user_id);


--
-- Name: composite_role constraint_composite_role; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT constraint_composite_role PRIMARY KEY (composite, child_role);


--
-- Name: credential_attribute constraint_credential_attr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential_attribute
    ADD CONSTRAINT constraint_credential_attr PRIMARY KEY (id);


--
-- Name: client_session_prot_mapper constraint_cs_pmp_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_prot_mapper
    ADD CONSTRAINT constraint_cs_pmp_pk PRIMARY KEY (client_session, protocol_mapper_id);


--
-- Name: identity_provider_config constraint_d; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT constraint_d PRIMARY KEY (identity_provider_id, name);


--
-- Name: policy_config constraint_dpc; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT constraint_dpc PRIMARY KEY (policy_id, name);


--
-- Name: realm_smtp_config constraint_e; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT constraint_e PRIMARY KEY (realm_id, name);


--
-- Name: credential constraint_f; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT constraint_f PRIMARY KEY (id);


--
-- Name: user_federation_config constraint_f9; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT constraint_f9 PRIMARY KEY (user_federation_provider_id, name);


--
-- Name: resource_server_perm_ticket constraint_fapmt; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT constraint_fapmt PRIMARY KEY (id);


--
-- Name: resource_server_resource constraint_farsr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT constraint_farsr PRIMARY KEY (id);


--
-- Name: resource_server_policy constraint_farsrp; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT constraint_farsrp PRIMARY KEY (id);


--
-- Name: associated_policy constraint_farsrpap; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT constraint_farsrpap PRIMARY KEY (policy_id, associated_policy_id);


--
-- Name: resource_policy constraint_farsrpp; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT constraint_farsrpp PRIMARY KEY (resource_id, policy_id);


--
-- Name: resource_server_scope constraint_farsrs; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT constraint_farsrs PRIMARY KEY (id);


--
-- Name: resource_scope constraint_farsrsp; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT constraint_farsrsp PRIMARY KEY (resource_id, scope_id);


--
-- Name: scope_policy constraint_farsrsps; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT constraint_farsrsps PRIMARY KEY (scope_id, policy_id);


--
-- Name: user_entity constraint_fb; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT constraint_fb PRIMARY KEY (id);


--
-- Name: fed_credential_attribute constraint_fed_credential_attr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_credential_attribute
    ADD CONSTRAINT constraint_fed_credential_attr PRIMARY KEY (id);


--
-- Name: user_federation_mapper_config constraint_fedmapper_cfg_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT constraint_fedmapper_cfg_pm PRIMARY KEY (user_federation_mapper_id, name);


--
-- Name: user_federation_mapper constraint_fedmapperpm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT constraint_fedmapperpm PRIMARY KEY (id);


--
-- Name: fed_user_consent_cl_scope constraint_fgrntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_consent_cl_scope
    ADD CONSTRAINT constraint_fgrntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent_client_scope constraint_grntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT constraint_grntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent constraint_grntcsnt_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT constraint_grntcsnt_pm PRIMARY KEY (id);


--
-- Name: keycloak_group constraint_group; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT constraint_group PRIMARY KEY (id);


--
-- Name: group_attribute constraint_group_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT constraint_group_attribute_pk PRIMARY KEY (id);


--
-- Name: group_role_mapping constraint_group_role; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT constraint_group_role PRIMARY KEY (role_id, group_id);


--
-- Name: identity_provider_mapper constraint_idpm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT constraint_idpm PRIMARY KEY (id);


--
-- Name: idp_mapper_config constraint_idpmconfig; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT constraint_idpmconfig PRIMARY KEY (idp_mapper_id, name);


--
-- Name: migration_model constraint_migmod; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.migration_model
    ADD CONSTRAINT constraint_migmod PRIMARY KEY (id);


--
-- Name: offline_client_session constraint_offl_cl_ses_pk3; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.offline_client_session
    ADD CONSTRAINT constraint_offl_cl_ses_pk3 PRIMARY KEY (user_session_id, client_id, client_storage_provider, external_client_id, offline_flag);


--
-- Name: offline_user_session constraint_offl_us_ses_pk2; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.offline_user_session
    ADD CONSTRAINT constraint_offl_us_ses_pk2 PRIMARY KEY (user_session_id, offline_flag);


--
-- Name: protocol_mapper constraint_pcm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT constraint_pcm PRIMARY KEY (id);


--
-- Name: protocol_mapper_config constraint_pmconfig; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT constraint_pmconfig PRIMARY KEY (protocol_mapper_id, name);


--
-- Name: realm_default_roles constraint_realm_default_roles; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT constraint_realm_default_roles PRIMARY KEY (realm_id, role_id);


--
-- Name: redirect_uris constraint_redirect_uris; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT constraint_redirect_uris PRIMARY KEY (client_id, value);


--
-- Name: required_action_config constraint_req_act_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.required_action_config
    ADD CONSTRAINT constraint_req_act_cfg_pk PRIMARY KEY (required_action_id, name);


--
-- Name: required_action_provider constraint_req_act_prv_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT constraint_req_act_prv_pk PRIMARY KEY (id);


--
-- Name: user_required_action constraint_required_action; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT constraint_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: role_attribute constraint_role_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT constraint_role_attribute_pk PRIMARY KEY (id);


--
-- Name: user_attribute constraint_user_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT constraint_user_attribute_pk PRIMARY KEY (id);


--
-- Name: user_group_membership constraint_user_group; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT constraint_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: user_session_note constraint_usn_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_session_note
    ADD CONSTRAINT constraint_usn_pk PRIMARY KEY (user_session, name);


--
-- Name: web_origins constraint_web_origins; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT constraint_web_origins PRIMARY KEY (client_id, value);


--
-- Name: client_scope_attributes pk_cl_tmpl_attr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT pk_cl_tmpl_attr PRIMARY KEY (scope_id, name);


--
-- Name: client_scope pk_cli_template; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT pk_cli_template PRIMARY KEY (id);


--
-- Name: databasechangeloglock pk_databasechangeloglock; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.databasechangeloglock
    ADD CONSTRAINT pk_databasechangeloglock PRIMARY KEY (id);


--
-- Name: resource_server pk_resource_server; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server
    ADD CONSTRAINT pk_resource_server PRIMARY KEY (id);


--
-- Name: client_scope_role_mapping pk_template_scope; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT pk_template_scope PRIMARY KEY (scope_id, role_id);


--
-- Name: default_client_scope r_def_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT r_def_cli_scope_bind PRIMARY KEY (realm_id, scope_id);


--
-- Name: resource_attribute res_attr_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT res_attr_pk PRIMARY KEY (id);


--
-- Name: keycloak_group sibling_names; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT sibling_names UNIQUE (realm_id, parent_group, name);


--
-- Name: identity_provider uk_2daelwnibji49avxsrtuf6xj33; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT uk_2daelwnibji49avxsrtuf6xj33 UNIQUE (provider_alias, realm_id);


--
-- Name: client_default_roles uk_8aelwnibji49avxsrtuf6xjow; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT uk_8aelwnibji49avxsrtuf6xjow UNIQUE (role_id);


--
-- Name: client uk_b71cjlbenv945rb6gcon438at; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT uk_b71cjlbenv945rb6gcon438at UNIQUE (realm_id, client_id);


--
-- Name: client_scope uk_cli_scope; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT uk_cli_scope UNIQUE (realm_id, name);


--
-- Name: user_entity uk_dykn684sl8up1crfei6eckhd7; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_dykn684sl8up1crfei6eckhd7 UNIQUE (realm_id, email_constraint);


--
-- Name: resource_server_resource uk_frsr6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5ha6 UNIQUE (name, owner, resource_server_id);


--
-- Name: resource_server_perm_ticket uk_frsr6t700s9v50bu18ws5pmt; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5pmt UNIQUE (owner, requester, resource_server_id, resource_id, scope_id);


--
-- Name: resource_server_policy uk_frsrpt700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT uk_frsrpt700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: resource_server_scope uk_frsrst700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT uk_frsrst700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: realm_default_roles uk_h4wpd7w4hsoolni3h0sw7btje; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT uk_h4wpd7w4hsoolni3h0sw7btje UNIQUE (role_id);


--
-- Name: user_consent uk_jkuwuvd56ontgsuhogm8uewrt; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT uk_jkuwuvd56ontgsuhogm8uewrt UNIQUE (client_id, client_storage_provider, external_client_id, user_id);


--
-- Name: realm uk_orvsdmla56612eaefiq6wl5oi; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT uk_orvsdmla56612eaefiq6wl5oi UNIQUE (name);


--
-- Name: user_entity uk_ru8tt6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_ru8tt6t700s9v50bu18ws5ha6 UNIQUE (realm_id, username);


--
-- Name: idx_assoc_pol_assoc_pol_id; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_assoc_pol_assoc_pol_id ON public.associated_policy USING btree (associated_policy_id);


--
-- Name: idx_auth_config_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_config_realm ON public.authenticator_config USING btree (realm_id);


--
-- Name: idx_auth_exec_flow; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_exec_flow ON public.authentication_execution USING btree (flow_id);


--
-- Name: idx_auth_exec_realm_flow; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_exec_realm_flow ON public.authentication_execution USING btree (realm_id, flow_id);


--
-- Name: idx_auth_flow_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_flow_realm ON public.authentication_flow USING btree (realm_id);


--
-- Name: idx_cl_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_cl_clscope ON public.client_scope_client USING btree (scope_id);


--
-- Name: idx_client_def_roles_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_client_def_roles_client ON public.client_default_roles USING btree (client_id);


--
-- Name: idx_client_init_acc_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_client_init_acc_realm ON public.client_initial_access USING btree (realm_id);


--
-- Name: idx_client_session_session; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_client_session_session ON public.client_session USING btree (session_id);


--
-- Name: idx_clscope_attrs; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_attrs ON public.client_scope_attributes USING btree (scope_id);


--
-- Name: idx_clscope_cl; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_cl ON public.client_scope_client USING btree (client_id);


--
-- Name: idx_clscope_protmap; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_protmap ON public.protocol_mapper USING btree (client_scope_id);


--
-- Name: idx_clscope_role; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_role ON public.client_scope_role_mapping USING btree (scope_id);


--
-- Name: idx_compo_config_compo; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_compo_config_compo ON public.component_config USING btree (component_id);


--
-- Name: idx_component_provider_type; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_component_provider_type ON public.component USING btree (provider_type);


--
-- Name: idx_component_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_component_realm ON public.component USING btree (realm_id);


--
-- Name: idx_composite; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_composite ON public.composite_role USING btree (composite);


--
-- Name: idx_composite_child; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_composite_child ON public.composite_role USING btree (child_role);


--
-- Name: idx_credential_attr_cred; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_credential_attr_cred ON public.credential_attribute USING btree (credential_id);


--
-- Name: idx_defcls_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_defcls_realm ON public.default_client_scope USING btree (realm_id);


--
-- Name: idx_defcls_scope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_defcls_scope ON public.default_client_scope USING btree (scope_id);


--
-- Name: idx_fed_cred_attr_cred; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fed_cred_attr_cred ON public.fed_credential_attribute USING btree (credential_id);


--
-- Name: idx_fedidentity_feduser; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fedidentity_feduser ON public.federated_identity USING btree (federated_user_id);


--
-- Name: idx_fedidentity_user; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fedidentity_user ON public.federated_identity USING btree (user_id);


--
-- Name: idx_fu_attribute; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_attribute ON public.fed_user_attribute USING btree (user_id, realm_id, name);


--
-- Name: idx_fu_cnsnt_ext; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_cnsnt_ext ON public.fed_user_consent USING btree (user_id, client_storage_provider, external_client_id);


--
-- Name: idx_fu_consent; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_consent ON public.fed_user_consent USING btree (user_id, client_id);


--
-- Name: idx_fu_consent_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_consent_ru ON public.fed_user_consent USING btree (realm_id, user_id);


--
-- Name: idx_fu_credential; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_credential ON public.fed_user_credential USING btree (user_id, type);


--
-- Name: idx_fu_credential_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_credential_ru ON public.fed_user_credential USING btree (realm_id, user_id);


--
-- Name: idx_fu_group_membership; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_group_membership ON public.fed_user_group_membership USING btree (user_id, group_id);


--
-- Name: idx_fu_group_membership_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_group_membership_ru ON public.fed_user_group_membership USING btree (realm_id, user_id);


--
-- Name: idx_fu_required_action; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_required_action ON public.fed_user_required_action USING btree (user_id, required_action);


--
-- Name: idx_fu_required_action_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_required_action_ru ON public.fed_user_required_action USING btree (realm_id, user_id);


--
-- Name: idx_fu_role_mapping; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_role_mapping ON public.fed_user_role_mapping USING btree (user_id, role_id);


--
-- Name: idx_fu_role_mapping_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_role_mapping_ru ON public.fed_user_role_mapping USING btree (realm_id, user_id);


--
-- Name: idx_group_attr_group; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_group_attr_group ON public.group_attribute USING btree (group_id);


--
-- Name: idx_group_role_mapp_group; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_group_role_mapp_group ON public.group_role_mapping USING btree (group_id);


--
-- Name: idx_id_prov_mapp_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_id_prov_mapp_realm ON public.identity_provider_mapper USING btree (realm_id);


--
-- Name: idx_ident_prov_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_ident_prov_realm ON public.identity_provider USING btree (realm_id);


--
-- Name: idx_keycloak_role_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_keycloak_role_client ON public.keycloak_role USING btree (client);


--
-- Name: idx_keycloak_role_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_keycloak_role_realm ON public.keycloak_role USING btree (realm);


--
-- Name: idx_offline_uss_createdon; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_offline_uss_createdon ON public.offline_user_session USING btree (created_on);


--
-- Name: idx_protocol_mapper_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_protocol_mapper_client ON public.protocol_mapper USING btree (client_id);


--
-- Name: idx_realm_attr_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_attr_realm ON public.realm_attribute USING btree (realm_id);


--
-- Name: idx_realm_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_clscope ON public.client_scope USING btree (realm_id);


--
-- Name: idx_realm_def_grp_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_def_grp_realm ON public.realm_default_groups USING btree (realm_id);


--
-- Name: idx_realm_def_roles_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_def_roles_realm ON public.realm_default_roles USING btree (realm_id);


--
-- Name: idx_realm_evt_list_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_evt_list_realm ON public.realm_events_listeners USING btree (realm_id);


--
-- Name: idx_realm_evt_types_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_evt_types_realm ON public.realm_enabled_event_types USING btree (realm_id);


--
-- Name: idx_realm_master_adm_cli; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_master_adm_cli ON public.realm USING btree (master_admin_client);


--
-- Name: idx_realm_supp_local_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_supp_local_realm ON public.realm_supported_locales USING btree (realm_id);


--
-- Name: idx_redir_uri_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_redir_uri_client ON public.redirect_uris USING btree (client_id);


--
-- Name: idx_req_act_prov_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_req_act_prov_realm ON public.required_action_provider USING btree (realm_id);


--
-- Name: idx_res_policy_policy; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_policy_policy ON public.resource_policy USING btree (policy_id);


--
-- Name: idx_res_scope_scope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_scope_scope ON public.resource_scope USING btree (scope_id);


--
-- Name: idx_res_serv_pol_res_serv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_serv_pol_res_serv ON public.resource_server_policy USING btree (resource_server_id);


--
-- Name: idx_res_srv_res_res_srv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_srv_res_res_srv ON public.resource_server_resource USING btree (resource_server_id);


--
-- Name: idx_res_srv_scope_res_srv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_srv_scope_res_srv ON public.resource_server_scope USING btree (resource_server_id);


--
-- Name: idx_role_attribute; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_role_attribute ON public.role_attribute USING btree (role_id);


--
-- Name: idx_role_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_role_clscope ON public.client_scope_role_mapping USING btree (role_id);


--
-- Name: idx_scope_mapping_role; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_scope_mapping_role ON public.scope_mapping USING btree (role_id);


--
-- Name: idx_scope_policy_policy; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_scope_policy_policy ON public.scope_policy USING btree (policy_id);


--
-- Name: idx_us_sess_id_on_cl_sess; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_us_sess_id_on_cl_sess ON public.offline_client_session USING btree (user_session_id);


--
-- Name: idx_usconsent_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usconsent_clscope ON public.user_consent_client_scope USING btree (user_consent_id);


--
-- Name: idx_user_attribute; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_attribute ON public.user_attribute USING btree (user_id);


--
-- Name: idx_user_consent; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_consent ON public.user_consent USING btree (user_id);


--
-- Name: idx_user_credential; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_credential ON public.credential USING btree (user_id);


--
-- Name: idx_user_email; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_email ON public.user_entity USING btree (email);


--
-- Name: idx_user_group_mapping; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_group_mapping ON public.user_group_membership USING btree (user_id);


--
-- Name: idx_user_reqactions; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_reqactions ON public.user_required_action USING btree (user_id);


--
-- Name: idx_user_role_mapping; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_role_mapping ON public.user_role_mapping USING btree (user_id);


--
-- Name: idx_usr_fed_map_fed_prv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usr_fed_map_fed_prv ON public.user_federation_mapper USING btree (federation_provider_id);


--
-- Name: idx_usr_fed_map_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usr_fed_map_realm ON public.user_federation_mapper USING btree (realm_id);


--
-- Name: idx_usr_fed_prv_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usr_fed_prv_realm ON public.user_federation_provider USING btree (realm_id);


--
-- Name: idx_web_orig_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_web_orig_client ON public.web_origins USING btree (client_id);


--
-- Name: client_session_auth_status auth_status_constraint; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_auth_status
    ADD CONSTRAINT auth_status_constraint FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: identity_provider fk2b4ebc52ae5c3b34; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT fk2b4ebc52ae5c3b34 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_attributes fk3c47c64beacca966; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT fk3c47c64beacca966 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: federated_identity fk404288b92ef007a6; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT fk404288b92ef007a6 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_node_registrations fk4129723ba992f594; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT fk4129723ba992f594 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_session_note fk5edfb00ff51c2736; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_note
    ADD CONSTRAINT fk5edfb00ff51c2736 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: user_session_note fk5edfb00ff51d3472; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_session_note
    ADD CONSTRAINT fk5edfb00ff51d3472 FOREIGN KEY (user_session) REFERENCES public.user_session(id);


--
-- Name: client_session_role fk_11b7sgqw18i532811v7o2dv76; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_role
    ADD CONSTRAINT fk_11b7sgqw18i532811v7o2dv76 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: redirect_uris fk_1burs8pb4ouj97h5wuppahv9f; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT fk_1burs8pb4ouj97h5wuppahv9f FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: user_federation_provider fk_1fj32f6ptolw2qy60cd8n01e8; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT fk_1fj32f6ptolw2qy60cd8n01e8 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_session_prot_mapper fk_33a8sgqw18i532811v7o2dk89; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_prot_mapper
    ADD CONSTRAINT fk_33a8sgqw18i532811v7o2dk89 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: realm_required_credential fk_5hg65lybevavkqfki3kponh9v; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT fk_5hg65lybevavkqfki3kponh9v FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_attribute fk_5hrm2vlf9ql5fu022kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu022kqepovbr FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: user_attribute fk_5hrm2vlf9ql5fu043kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu043kqepovbr FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: user_required_action fk_6qj3w1jw9cvafhe19bwsiuvmd; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT fk_6qj3w1jw9cvafhe19bwsiuvmd FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: keycloak_role fk_6vyqfe4cn4wlq8r6kt5vdsj5c; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_6vyqfe4cn4wlq8r6kt5vdsj5c FOREIGN KEY (realm) REFERENCES public.realm(id);


--
-- Name: realm_smtp_config fk_70ej8xdxgxd0b9hh6180irr0o; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT fk_70ej8xdxgxd0b9hh6180irr0o FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_default_roles fk_8aelwnibji49avxsrtuf6xjow; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT fk_8aelwnibji49avxsrtuf6xjow FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_attribute fk_8shxd6l3e9atqukacxgpffptw; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT fk_8shxd6l3e9atqukacxgpffptw FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: composite_role fk_a63wvekftu8jo1pnj81e7mce2; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_a63wvekftu8jo1pnj81e7mce2 FOREIGN KEY (composite) REFERENCES public.keycloak_role(id);


--
-- Name: authentication_execution fk_auth_exec_flow; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_flow FOREIGN KEY (flow_id) REFERENCES public.authentication_flow(id);


--
-- Name: authentication_execution fk_auth_exec_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authentication_flow fk_auth_flow_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT fk_auth_flow_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authenticator_config fk_auth_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT fk_auth_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_session fk_b4ao2vcvat6ukau74wbwtfqo1; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session
    ADD CONSTRAINT fk_b4ao2vcvat6ukau74wbwtfqo1 FOREIGN KEY (session_id) REFERENCES public.user_session(id);


--
-- Name: user_role_mapping fk_c4fqv34p1mbylloxang7b1q3l; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT fk_c4fqv34p1mbylloxang7b1q3l FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_scope_client fk_c_cli_scope_client; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT fk_c_cli_scope_client FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_scope_client fk_c_cli_scope_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT fk_c_cli_scope_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_attributes fk_cl_scope_attr_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT fk_cl_scope_attr_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_role; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_role FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_user_session_note fk_cl_usr_ses_note; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_user_session_note
    ADD CONSTRAINT fk_cl_usr_ses_note FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: protocol_mapper fk_cli_scope_mapper; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_cli_scope_mapper FOREIGN KEY (client_scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_initial_access fk_client_init_acc_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT fk_client_init_acc_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: component_config fk_component_config; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT fk_component_config FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: component fk_component_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT fk_component_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: credential_attribute fk_cred_attr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential_attribute
    ADD CONSTRAINT fk_cred_attr FOREIGN KEY (credential_id) REFERENCES public.credential(id);


--
-- Name: realm_default_groups fk_def_groups_group; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: realm_default_groups fk_def_groups_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_default_roles fk_evudb1ppw84oxfax2drs03icc; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT fk_evudb1ppw84oxfax2drs03icc FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: fed_credential_attribute fk_fed_cred_attr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_credential_attribute
    ADD CONSTRAINT fk_fed_cred_attr FOREIGN KEY (credential_id) REFERENCES public.fed_user_credential(id);


--
-- Name: user_federation_mapper_config fk_fedmapper_cfg; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT fk_fedmapper_cfg FOREIGN KEY (user_federation_mapper_id) REFERENCES public.user_federation_mapper(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_fedprv; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_fedprv FOREIGN KEY (federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: associated_policy fk_frsr5s213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsr5s213xcx4wnkog82ssrfy FOREIGN KEY (associated_policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrasp13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrasp13xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog82sspmt; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82sspmt FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_resource fk_frsrho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog83sspmt; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog83sspmt FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog84sspmt; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog84sspmt FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: associated_policy fk_frsrpas14xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsrpas14xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrpass3xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrpass3xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_perm_ticket fk_frsrpo2128cx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrpo2128cx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_policy fk_frsrpo213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT fk_frsrpo213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_scope fk_frsrpos13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrpos13xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpos53xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpos53xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpp213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpp213xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_scope fk_frsrps213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrps213xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_scope fk_frsrso213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT fk_frsrso213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: composite_role fk_gr7thllb9lu8q4vqa4524jjy8; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_gr7thllb9lu8q4vqa4524jjy8 FOREIGN KEY (child_role) REFERENCES public.keycloak_role(id);


--
-- Name: user_consent_client_scope fk_grntcsnt_clsc_usc; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT fk_grntcsnt_clsc_usc FOREIGN KEY (user_consent_id) REFERENCES public.user_consent(id);


--
-- Name: user_consent fk_grntcsnt_user; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT fk_grntcsnt_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: group_attribute fk_group_attribute_group; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT fk_group_attribute_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: keycloak_group fk_group_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT fk_group_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: group_role_mapping fk_group_role_group; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: group_role_mapping fk_group_role_role; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_role FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_default_roles fk_h4wpd7w4hsoolni3h0sw7btje; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT fk_h4wpd7w4hsoolni3h0sw7btje FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_enabled_event_types fk_h846o4h0w8epx5nwedrf5y69j; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT fk_h846o4h0w8epx5nwedrf5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_events_listeners fk_h846o4h0w8epx5nxev9f5y69j; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT fk_h846o4h0w8epx5nxev9f5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: identity_provider_mapper fk_idpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT fk_idpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: idp_mapper_config fk_idpmconfig; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT fk_idpmconfig FOREIGN KEY (idp_mapper_id) REFERENCES public.identity_provider_mapper(id);


--
-- Name: keycloak_role fk_kjho5le2c0ral09fl8cm9wfw9; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_kjho5le2c0ral09fl8cm9wfw9 FOREIGN KEY (client) REFERENCES public.client(id);


--
-- Name: web_origins fk_lojpho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT fk_lojpho213xcx4wnkog82ssrfy FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_default_roles fk_nuilts7klwqw2h8m2b5joytky; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT fk_nuilts7klwqw2h8m2b5joytky FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: scope_mapping fk_ouse064plmlr732lxjcn1q5f1; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_ouse064plmlr732lxjcn1q5f1 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: scope_mapping fk_p3rh9grku11kqfrs4fltt7rnq; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_p3rh9grku11kqfrs4fltt7rnq FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: client fk_p56ctinxxb9gsk57fo49f9tac; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT fk_p56ctinxxb9gsk57fo49f9tac FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: protocol_mapper fk_pcm_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_pcm_realm FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: credential fk_pfyr0glasqyl0dei3kl69r6v0; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT fk_pfyr0glasqyl0dei3kl69r6v0 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: protocol_mapper_config fk_pmconfig; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT fk_pmconfig FOREIGN KEY (protocol_mapper_id) REFERENCES public.protocol_mapper(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope fk_realm_cli_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT fk_realm_cli_scope FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: required_action_provider fk_req_act_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT fk_req_act_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_uris fk_resource_server_uris; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT fk_resource_server_uris FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: role_attribute fk_role_attribute_id; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT fk_role_attribute_id FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_supported_locales fk_supported_locales_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT fk_supported_locales_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_federation_config fk_t13hpu1j94r2ebpekr39x5eu5; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT fk_t13hpu1j94r2ebpekr39x5eu5 FOREIGN KEY (user_federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: realm fk_traf444kk6qrkms7n56aiwq5y; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT fk_traf444kk6qrkms7n56aiwq5y FOREIGN KEY (master_admin_client) REFERENCES public.client(id);


--
-- Name: user_group_membership fk_user_group_user; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT fk_user_group_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: policy_config fkdc34197cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT fkdc34197cf864c4e43 FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: identity_provider_config fkdc4897cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT fkdc4897cf864c4e43 FOREIGN KEY (identity_provider_id) REFERENCES public.identity_provider(internal_id);


--
-- PostgreSQL database dump complete
--

\connect dbuser

SET default_transaction_read_only = off;

--
-- PostgreSQL database dump
--

-- Dumped from database version 10.4
-- Dumped by pg_dump version 10.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- PostgreSQL database dump complete
--

\connect flaminem

SET default_transaction_read_only = off;

--
-- PostgreSQL database dump
--

-- Dumped from database version 10.4
-- Dumped by pg_dump version 10.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: admin_event_entity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.admin_event_entity (
    id character varying(36) NOT NULL,
    admin_event_time bigint,
    realm_id character varying(255),
    operation_type character varying(255),
    auth_realm_id character varying(255),
    auth_client_id character varying(255),
    auth_user_id character varying(255),
    ip_address character varying(255),
    resource_path character varying(2550),
    representation text,
    error character varying(255),
    resource_type character varying(64)
);


ALTER TABLE public.admin_event_entity OWNER TO dbuser;

--
-- Name: associated_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.associated_policy (
    policy_id character varying(36) NOT NULL,
    associated_policy_id character varying(36) NOT NULL
);


ALTER TABLE public.associated_policy OWNER TO dbuser;

--
-- Name: authentication_execution; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authentication_execution (
    id character varying(36) NOT NULL,
    alias character varying(255),
    authenticator character varying(36),
    realm_id character varying(36),
    flow_id character varying(36),
    requirement integer,
    priority integer,
    authenticator_flow boolean DEFAULT false NOT NULL,
    auth_flow_id character varying(36),
    auth_config character varying(36)
);


ALTER TABLE public.authentication_execution OWNER TO dbuser;

--
-- Name: authentication_flow; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authentication_flow (
    id character varying(36) NOT NULL,
    alias character varying(255),
    description character varying(255),
    realm_id character varying(36),
    provider_id character varying(36) DEFAULT 'basic-flow'::character varying NOT NULL,
    top_level boolean DEFAULT false NOT NULL,
    built_in boolean DEFAULT false NOT NULL
);


ALTER TABLE public.authentication_flow OWNER TO dbuser;

--
-- Name: authenticator_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authenticator_config (
    id character varying(36) NOT NULL,
    alias character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.authenticator_config OWNER TO dbuser;

--
-- Name: authenticator_config_entry; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authenticator_config_entry (
    authenticator_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.authenticator_config_entry OWNER TO dbuser;

--
-- Name: broker_link; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.broker_link (
    identity_provider character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL,
    broker_user_id character varying(255),
    broker_username character varying(255),
    token text,
    user_id character varying(255) NOT NULL
);


ALTER TABLE public.broker_link OWNER TO dbuser;

--
-- Name: client; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client (
    id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    full_scope_allowed boolean DEFAULT false NOT NULL,
    client_id character varying(255),
    not_before integer,
    public_client boolean DEFAULT false NOT NULL,
    secret character varying(255),
    base_url character varying(255),
    bearer_only boolean DEFAULT false NOT NULL,
    management_url character varying(255),
    surrogate_auth_required boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    protocol character varying(255),
    node_rereg_timeout integer DEFAULT 0,
    frontchannel_logout boolean DEFAULT false NOT NULL,
    consent_required boolean DEFAULT false NOT NULL,
    name character varying(255),
    service_accounts_enabled boolean DEFAULT false NOT NULL,
    client_authenticator_type character varying(255),
    root_url character varying(255),
    description character varying(255),
    registration_token character varying(255),
    standard_flow_enabled boolean DEFAULT true NOT NULL,
    implicit_flow_enabled boolean DEFAULT false NOT NULL,
    direct_access_grants_enabled boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client OWNER TO dbuser;

--
-- Name: client_attributes; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_attributes (
    client_id character varying(36) NOT NULL,
    value character varying(4000),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_attributes OWNER TO dbuser;

--
-- Name: client_auth_flow_bindings; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_auth_flow_bindings (
    client_id character varying(36) NOT NULL,
    flow_id character varying(36),
    binding_name character varying(255) NOT NULL
);


ALTER TABLE public.client_auth_flow_bindings OWNER TO dbuser;

--
-- Name: client_default_roles; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_default_roles (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_default_roles OWNER TO dbuser;

--
-- Name: client_initial_access; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_initial_access (
    id character varying(36) NOT NULL,
    realm_id character varying(36) NOT NULL,
    "timestamp" integer,
    expiration integer,
    count integer,
    remaining_count integer
);


ALTER TABLE public.client_initial_access OWNER TO dbuser;

--
-- Name: client_node_registrations; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_node_registrations (
    client_id character varying(36) NOT NULL,
    value integer,
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_node_registrations OWNER TO dbuser;

--
-- Name: client_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope (
    id character varying(36) NOT NULL,
    name character varying(255),
    realm_id character varying(36),
    description character varying(255),
    protocol character varying(255)
);


ALTER TABLE public.client_scope OWNER TO dbuser;

--
-- Name: client_scope_attributes; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope_attributes (
    scope_id character varying(36) NOT NULL,
    value character varying(2048),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_scope_attributes OWNER TO dbuser;

--
-- Name: client_scope_client; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope_client (
    client_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client_scope_client OWNER TO dbuser;

--
-- Name: client_scope_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope_role_mapping (
    scope_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_scope_role_mapping OWNER TO dbuser;

--
-- Name: client_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    redirect_uri character varying(255),
    state character varying(255),
    "timestamp" integer,
    session_id character varying(36),
    auth_method character varying(255),
    realm_id character varying(255),
    auth_user_id character varying(36),
    current_action character varying(36)
);


ALTER TABLE public.client_session OWNER TO dbuser;

--
-- Name: client_session_auth_status; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_auth_status (
    authenticator character varying(36) NOT NULL,
    status integer,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_auth_status OWNER TO dbuser;

--
-- Name: client_session_note; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_note (
    name character varying(255) NOT NULL,
    value character varying(255),
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_note OWNER TO dbuser;

--
-- Name: client_session_prot_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_prot_mapper (
    protocol_mapper_id character varying(36) NOT NULL,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_prot_mapper OWNER TO dbuser;

--
-- Name: client_session_role; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_role (
    role_id character varying(255) NOT NULL,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_role OWNER TO dbuser;

--
-- Name: client_user_session_note; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_user_session_note (
    name character varying(255) NOT NULL,
    value character varying(2048),
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_user_session_note OWNER TO dbuser;

--
-- Name: component; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.component (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_id character varying(36),
    provider_id character varying(36),
    provider_type character varying(255),
    realm_id character varying(36),
    sub_type character varying(255)
);


ALTER TABLE public.component OWNER TO dbuser;

--
-- Name: component_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.component_config (
    id character varying(36) NOT NULL,
    component_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.component_config OWNER TO dbuser;

--
-- Name: composite_role; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.composite_role (
    composite character varying(36) NOT NULL,
    child_role character varying(36) NOT NULL
);


ALTER TABLE public.composite_role OWNER TO dbuser;

--
-- Name: credential; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.credential (
    id character varying(36) NOT NULL,
    device character varying(255),
    hash_iterations integer,
    salt bytea,
    type character varying(255),
    value character varying(4000),
    user_id character varying(36),
    created_date bigint,
    counter integer DEFAULT 0,
    digits integer DEFAULT 6,
    period integer DEFAULT 30,
    algorithm character varying(36) DEFAULT NULL::character varying
);


ALTER TABLE public.credential OWNER TO dbuser;

--
-- Name: credential_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.credential_attribute (
    id character varying(36) NOT NULL,
    credential_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.credential_attribute OWNER TO dbuser;

--
-- Name: databasechangelog; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.databasechangelog (
    id character varying(255) NOT NULL,
    author character varying(255) NOT NULL,
    filename character varying(255) NOT NULL,
    dateexecuted timestamp without time zone NOT NULL,
    orderexecuted integer NOT NULL,
    exectype character varying(10) NOT NULL,
    md5sum character varying(35),
    description character varying(255),
    comments character varying(255),
    tag character varying(255),
    liquibase character varying(20),
    contexts character varying(255),
    labels character varying(255),
    deployment_id character varying(10)
);


ALTER TABLE public.databasechangelog OWNER TO dbuser;

--
-- Name: databasechangeloglock; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.databasechangeloglock (
    id integer NOT NULL,
    locked boolean NOT NULL,
    lockgranted timestamp without time zone,
    lockedby character varying(255)
);


ALTER TABLE public.databasechangeloglock OWNER TO dbuser;

--
-- Name: default_client_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.default_client_scope (
    realm_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.default_client_scope OWNER TO dbuser;

--
-- Name: event_entity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.event_entity (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    details_json character varying(2550),
    error character varying(255),
    ip_address character varying(255),
    realm_id character varying(255),
    session_id character varying(255),
    event_time bigint,
    type character varying(255),
    user_id character varying(255)
);


ALTER TABLE public.event_entity OWNER TO dbuser;

--
-- Name: fed_credential_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_credential_attribute (
    id character varying(36) NOT NULL,
    credential_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.fed_credential_attribute OWNER TO dbuser;

--
-- Name: fed_user_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_attribute (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    value character varying(2024)
);


ALTER TABLE public.fed_user_attribute OWNER TO dbuser;

--
-- Name: fed_user_consent; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.fed_user_consent OWNER TO dbuser;

--
-- Name: fed_user_consent_cl_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_consent_cl_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.fed_user_consent_cl_scope OWNER TO dbuser;

--
-- Name: fed_user_credential; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_credential (
    id character varying(36) NOT NULL,
    device character varying(255),
    hash_iterations integer,
    salt bytea,
    type character varying(255),
    value character varying(255),
    created_date bigint,
    counter integer DEFAULT 0,
    digits integer DEFAULT 6,
    period integer DEFAULT 30,
    algorithm character varying(36) DEFAULT 'HmacSHA1'::character varying,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_credential OWNER TO dbuser;

--
-- Name: fed_user_group_membership; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_group_membership OWNER TO dbuser;

--
-- Name: fed_user_required_action; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_required_action (
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_required_action OWNER TO dbuser;

--
-- Name: fed_user_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_role_mapping (
    role_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_role_mapping OWNER TO dbuser;

--
-- Name: federated_identity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.federated_identity (
    identity_provider character varying(255) NOT NULL,
    realm_id character varying(36),
    federated_user_id character varying(255),
    federated_username character varying(255),
    token text,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_identity OWNER TO dbuser;

--
-- Name: federated_user; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.federated_user (
    id character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_user OWNER TO dbuser;

--
-- Name: group_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.group_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_attribute OWNER TO dbuser;

--
-- Name: group_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.group_role_mapping (
    role_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_role_mapping OWNER TO dbuser;

--
-- Name: identity_provider; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.identity_provider (
    internal_id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    provider_alias character varying(255),
    provider_id character varying(255),
    store_token boolean DEFAULT false NOT NULL,
    authenticate_by_default boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    add_token_role boolean DEFAULT true NOT NULL,
    trust_email boolean DEFAULT false NOT NULL,
    first_broker_login_flow_id character varying(36),
    post_broker_login_flow_id character varying(36),
    provider_display_name character varying(255),
    link_only boolean DEFAULT false NOT NULL
);


ALTER TABLE public.identity_provider OWNER TO dbuser;

--
-- Name: identity_provider_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.identity_provider_config (
    identity_provider_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.identity_provider_config OWNER TO dbuser;

--
-- Name: identity_provider_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.identity_provider_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    idp_alias character varying(255) NOT NULL,
    idp_mapper_name character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.identity_provider_mapper OWNER TO dbuser;

--
-- Name: idp_mapper_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.idp_mapper_config (
    idp_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.idp_mapper_config OWNER TO dbuser;

--
-- Name: keycloak_group; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.keycloak_group (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_group character varying(36),
    realm_id character varying(36)
);


ALTER TABLE public.keycloak_group OWNER TO dbuser;

--
-- Name: keycloak_role; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.keycloak_role (
    id character varying(36) NOT NULL,
    client_realm_constraint character varying(36),
    client_role boolean DEFAULT false NOT NULL,
    description character varying(255),
    name character varying(255),
    realm_id character varying(255),
    client character varying(36),
    realm character varying(36)
);


ALTER TABLE public.keycloak_role OWNER TO dbuser;

--
-- Name: migration_model; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.migration_model (
    id character varying(36) NOT NULL,
    version character varying(36)
);


ALTER TABLE public.migration_model OWNER TO dbuser;

--
-- Name: offline_client_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.offline_client_session (
    user_session_id character varying(36) NOT NULL,
    client_id character varying(36) NOT NULL,
    offline_flag character varying(4) NOT NULL,
    "timestamp" integer,
    data text,
    client_storage_provider character varying(36) DEFAULT 'local'::character varying NOT NULL,
    external_client_id character varying(255) DEFAULT 'local'::character varying NOT NULL
);


ALTER TABLE public.offline_client_session OWNER TO dbuser;

--
-- Name: offline_user_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.offline_user_session (
    user_session_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    created_on integer NOT NULL,
    offline_flag character varying(4) NOT NULL,
    data text,
    last_session_refresh integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.offline_user_session OWNER TO dbuser;

--
-- Name: policy_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.policy_config (
    policy_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.policy_config OWNER TO dbuser;

--
-- Name: protocol_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.protocol_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    protocol character varying(255) NOT NULL,
    protocol_mapper_name character varying(255) NOT NULL,
    client_id character varying(36),
    client_scope_id character varying(36)
);


ALTER TABLE public.protocol_mapper OWNER TO dbuser;

--
-- Name: protocol_mapper_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.protocol_mapper_config (
    protocol_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.protocol_mapper_config OWNER TO dbuser;

--
-- Name: realm; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm (
    id character varying(36) NOT NULL,
    access_code_lifespan integer,
    user_action_lifespan integer,
    access_token_lifespan integer,
    account_theme character varying(255),
    admin_theme character varying(255),
    email_theme character varying(255),
    enabled boolean DEFAULT false NOT NULL,
    events_enabled boolean DEFAULT false NOT NULL,
    events_expiration bigint,
    login_theme character varying(255),
    name character varying(255),
    not_before integer,
    password_policy character varying(2550),
    registration_allowed boolean DEFAULT false NOT NULL,
    remember_me boolean DEFAULT false NOT NULL,
    reset_password_allowed boolean DEFAULT false NOT NULL,
    social boolean DEFAULT false NOT NULL,
    ssl_required character varying(255),
    sso_idle_timeout integer,
    sso_max_lifespan integer,
    update_profile_on_soc_login boolean DEFAULT false NOT NULL,
    verify_email boolean DEFAULT false NOT NULL,
    master_admin_client character varying(36),
    login_lifespan integer,
    internationalization_enabled boolean DEFAULT false NOT NULL,
    default_locale character varying(255),
    reg_email_as_username boolean DEFAULT false NOT NULL,
    admin_events_enabled boolean DEFAULT false NOT NULL,
    admin_events_details_enabled boolean DEFAULT false NOT NULL,
    edit_username_allowed boolean DEFAULT false NOT NULL,
    otp_policy_counter integer DEFAULT 0,
    otp_policy_window integer DEFAULT 1,
    otp_policy_period integer DEFAULT 30,
    otp_policy_digits integer DEFAULT 6,
    otp_policy_alg character varying(36) DEFAULT 'HmacSHA1'::character varying,
    otp_policy_type character varying(36) DEFAULT 'totp'::character varying,
    browser_flow character varying(36),
    registration_flow character varying(36),
    direct_grant_flow character varying(36),
    reset_credentials_flow character varying(36),
    client_auth_flow character varying(36),
    offline_session_idle_timeout integer DEFAULT 0,
    revoke_refresh_token boolean DEFAULT false NOT NULL,
    access_token_life_implicit integer DEFAULT 0,
    login_with_email_allowed boolean DEFAULT true NOT NULL,
    duplicate_emails_allowed boolean DEFAULT false NOT NULL,
    docker_auth_flow character varying(36),
    refresh_token_max_reuse integer DEFAULT 0,
    allow_user_managed_access boolean DEFAULT false NOT NULL,
    sso_max_lifespan_remember_me integer DEFAULT 0 NOT NULL,
    sso_idle_timeout_remember_me integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.realm OWNER TO dbuser;

--
-- Name: realm_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_attribute OWNER TO dbuser;

--
-- Name: realm_default_groups; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_default_groups (
    realm_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_groups OWNER TO dbuser;

--
-- Name: realm_default_roles; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_default_roles (
    realm_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_roles OWNER TO dbuser;

--
-- Name: realm_enabled_event_types; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_enabled_event_types (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_enabled_event_types OWNER TO dbuser;

--
-- Name: realm_events_listeners; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_events_listeners (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_events_listeners OWNER TO dbuser;

--
-- Name: realm_required_credential; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_required_credential (
    type character varying(255) NOT NULL,
    form_label character varying(255),
    input boolean DEFAULT false NOT NULL,
    secret boolean DEFAULT false NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_required_credential OWNER TO dbuser;

--
-- Name: realm_smtp_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_smtp_config (
    realm_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.realm_smtp_config OWNER TO dbuser;

--
-- Name: realm_supported_locales; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_supported_locales (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_supported_locales OWNER TO dbuser;

--
-- Name: redirect_uris; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.redirect_uris (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.redirect_uris OWNER TO dbuser;

--
-- Name: required_action_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.required_action_config (
    required_action_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.required_action_config OWNER TO dbuser;

--
-- Name: required_action_provider; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.required_action_provider (
    id character varying(36) NOT NULL,
    alias character varying(255),
    name character varying(255),
    realm_id character varying(36),
    enabled boolean DEFAULT false NOT NULL,
    default_action boolean DEFAULT false NOT NULL,
    provider_id character varying(255),
    priority integer
);


ALTER TABLE public.required_action_provider OWNER TO dbuser;

--
-- Name: resource_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    resource_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_attribute OWNER TO dbuser;

--
-- Name: resource_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_policy (
    resource_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_policy OWNER TO dbuser;

--
-- Name: resource_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_scope (
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_scope OWNER TO dbuser;

--
-- Name: resource_server; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server (
    id character varying(36) NOT NULL,
    allow_rs_remote_mgmt boolean DEFAULT false NOT NULL,
    policy_enforce_mode character varying(15) NOT NULL,
    decision_strategy smallint DEFAULT 1 NOT NULL
);


ALTER TABLE public.resource_server OWNER TO dbuser;

--
-- Name: resource_server_perm_ticket; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_perm_ticket (
    id character varying(36) NOT NULL,
    owner character varying(36) NOT NULL,
    requester character varying(36) NOT NULL,
    created_timestamp bigint NOT NULL,
    granted_timestamp bigint,
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36),
    resource_server_id character varying(36) NOT NULL,
    policy_id character varying(36)
);


ALTER TABLE public.resource_server_perm_ticket OWNER TO dbuser;

--
-- Name: resource_server_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_policy (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255),
    type character varying(255) NOT NULL,
    decision_strategy character varying(20),
    logic character varying(20),
    resource_server_id character varying(36) NOT NULL,
    owner character varying(36)
);


ALTER TABLE public.resource_server_policy OWNER TO dbuser;

--
-- Name: resource_server_resource; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_resource (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    type character varying(255),
    icon_uri character varying(255),
    owner character varying(36) NOT NULL,
    resource_server_id character varying(36) NOT NULL,
    owner_managed_access boolean DEFAULT false NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_resource OWNER TO dbuser;

--
-- Name: resource_server_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_scope (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    icon_uri character varying(255),
    resource_server_id character varying(36) NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_scope OWNER TO dbuser;

--
-- Name: resource_uris; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_uris (
    resource_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.resource_uris OWNER TO dbuser;

--
-- Name: role_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.role_attribute (
    id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255)
);


ALTER TABLE public.role_attribute OWNER TO dbuser;

--
-- Name: scope_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.scope_mapping (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_mapping OWNER TO dbuser;

--
-- Name: scope_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.scope_policy (
    scope_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_policy OWNER TO dbuser;

--
-- Name: user_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    user_id character varying(36) NOT NULL,
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL
);


ALTER TABLE public.user_attribute OWNER TO dbuser;

--
-- Name: user_consent; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    user_id character varying(36) NOT NULL,
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.user_consent OWNER TO dbuser;

--
-- Name: user_consent_client_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_consent_client_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.user_consent_client_scope OWNER TO dbuser;

--
-- Name: user_entity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_entity (
    id character varying(36) NOT NULL,
    email character varying(255),
    email_constraint character varying(255),
    email_verified boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    federation_link character varying(255),
    first_name character varying(255),
    last_name character varying(255),
    realm_id character varying(255),
    username character varying(255),
    created_timestamp bigint,
    service_account_client_link character varying(36),
    not_before integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.user_entity OWNER TO dbuser;

--
-- Name: user_federation_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_config (
    user_federation_provider_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_config OWNER TO dbuser;

--
-- Name: user_federation_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    federation_provider_id character varying(36) NOT NULL,
    federation_mapper_type character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.user_federation_mapper OWNER TO dbuser;

--
-- Name: user_federation_mapper_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_mapper_config (
    user_federation_mapper_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_mapper_config OWNER TO dbuser;

--
-- Name: user_federation_provider; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_provider (
    id character varying(36) NOT NULL,
    changed_sync_period integer,
    display_name character varying(255),
    full_sync_period integer,
    last_sync integer,
    priority integer,
    provider_name character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.user_federation_provider OWNER TO dbuser;

--
-- Name: user_group_membership; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_group_membership OWNER TO dbuser;

--
-- Name: user_required_action; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_required_action (
    user_id character varying(36) NOT NULL,
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL
);


ALTER TABLE public.user_required_action OWNER TO dbuser;

--
-- Name: user_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_role_mapping (
    role_id character varying(255) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_role_mapping OWNER TO dbuser;

--
-- Name: user_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_session (
    id character varying(36) NOT NULL,
    auth_method character varying(255),
    ip_address character varying(255),
    last_session_refresh integer,
    login_username character varying(255),
    realm_id character varying(255),
    remember_me boolean DEFAULT false NOT NULL,
    started integer,
    user_id character varying(255),
    user_session_state integer,
    broker_session_id character varying(255),
    broker_user_id character varying(255)
);


ALTER TABLE public.user_session OWNER TO dbuser;

--
-- Name: user_session_note; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_session_note (
    user_session character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(2048)
);


ALTER TABLE public.user_session_note OWNER TO dbuser;

--
-- Name: username_login_failure; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.username_login_failure (
    realm_id character varying(36) NOT NULL,
    username character varying(255) NOT NULL,
    failed_login_not_before integer,
    last_failure bigint,
    last_ip_failure character varying(255),
    num_failures integer
);


ALTER TABLE public.username_login_failure OWNER TO dbuser;

--
-- Name: web_origins; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.web_origins (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.web_origins OWNER TO dbuser;

--
-- Data for Name: admin_event_entity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.admin_event_entity (id, admin_event_time, realm_id, operation_type, auth_realm_id, auth_client_id, auth_user_id, ip_address, resource_path, representation, error, resource_type) FROM stdin;
\.


--
-- Data for Name: associated_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.associated_policy (policy_id, associated_policy_id) FROM stdin;
\.


--
-- Data for Name: authentication_execution; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authentication_execution (id, alias, authenticator, realm_id, flow_id, requirement, priority, authenticator_flow, auth_flow_id, auth_config) FROM stdin;
f98b6bb3-615e-4161-a1ee-812bf29e8320	\N	auth-cookie	master	114581d0-6ef9-4a6a-b6ce-6ec08045422f	2	10	f	\N	\N
4636d3b2-7b56-4d36-8309-5cfc63319f28	\N	auth-spnego	master	114581d0-6ef9-4a6a-b6ce-6ec08045422f	3	20	f	\N	\N
f31518e5-d38c-4ede-a0b7-3f260380399e	\N	identity-provider-redirector	master	114581d0-6ef9-4a6a-b6ce-6ec08045422f	2	25	f	\N	\N
ab90a5e3-8cc7-409b-8a23-28344c351410	\N	\N	master	114581d0-6ef9-4a6a-b6ce-6ec08045422f	2	30	t	a7b5f447-cd97-41f9-894e-de15e8a277be	\N
6712c739-8600-4604-99db-e777bbba7e99	\N	auth-username-password-form	master	a7b5f447-cd97-41f9-894e-de15e8a277be	0	10	f	\N	\N
455fba04-014f-4c78-bb6e-ac6efd9e4eef	\N	auth-otp-form	master	a7b5f447-cd97-41f9-894e-de15e8a277be	1	20	f	\N	\N
746e6b23-a014-4a58-aa41-e1aacd27d6b9	\N	direct-grant-validate-username	master	7bc696c9-3787-4c74-8fbd-6a0c3ce02b91	0	10	f	\N	\N
c2a9568b-31fc-4df5-b8a0-e6776e6df6f8	\N	direct-grant-validate-password	master	7bc696c9-3787-4c74-8fbd-6a0c3ce02b91	0	20	f	\N	\N
7d6da868-24b2-499f-b9fe-8b6abebb0d09	\N	direct-grant-validate-otp	master	7bc696c9-3787-4c74-8fbd-6a0c3ce02b91	1	30	f	\N	\N
465f573c-1daa-40d8-93ff-ddee717092b7	\N	registration-page-form	master	7750c1f2-7d91-410a-aedd-7c5b43c5323b	0	10	t	8203f674-ed43-424a-ab34-376047681471	\N
e1c9ad00-9d26-4c8e-a3e3-3dade59b9490	\N	registration-user-creation	master	8203f674-ed43-424a-ab34-376047681471	0	20	f	\N	\N
54fb034f-4ad8-4c9b-b290-5a1d09110c17	\N	registration-profile-action	master	8203f674-ed43-424a-ab34-376047681471	0	40	f	\N	\N
d563843e-b039-4518-b133-74fc4df36aa6	\N	registration-password-action	master	8203f674-ed43-424a-ab34-376047681471	0	50	f	\N	\N
3f23f4e6-3040-42f9-8d55-7c0576ffe8a4	\N	registration-recaptcha-action	master	8203f674-ed43-424a-ab34-376047681471	3	60	f	\N	\N
d81c5893-4f05-4861-a552-9fe056731ce7	\N	reset-credentials-choose-user	master	dde9f98f-3689-42f9-9fc0-d27b814237ce	0	10	f	\N	\N
c3d02224-2d45-4fef-b4b4-bee7debea3bf	\N	reset-credential-email	master	dde9f98f-3689-42f9-9fc0-d27b814237ce	0	20	f	\N	\N
59a90c6b-4bed-41fa-a48f-bc1ce02cee5f	\N	reset-password	master	dde9f98f-3689-42f9-9fc0-d27b814237ce	0	30	f	\N	\N
a3059611-728f-48bf-84bb-7994f85ba228	\N	reset-otp	master	dde9f98f-3689-42f9-9fc0-d27b814237ce	1	40	f	\N	\N
3b51ca4e-3e39-4517-96ac-a422287929ff	\N	client-secret	master	a490b6cd-f301-4792-8de0-10bdfc82f48c	2	10	f	\N	\N
3daa3081-f4b9-47b9-8443-8ec97a3530a6	\N	client-jwt	master	a490b6cd-f301-4792-8de0-10bdfc82f48c	2	20	f	\N	\N
b69b0601-7671-4ff0-a919-cb70fcd0e21f	\N	client-secret-jwt	master	a490b6cd-f301-4792-8de0-10bdfc82f48c	2	30	f	\N	\N
809ccf43-1588-4fe9-922f-dc123800bb94	\N	client-x509	master	a490b6cd-f301-4792-8de0-10bdfc82f48c	2	40	f	\N	\N
b5c6d76b-208d-460e-9277-663f68fe43a8	\N	idp-review-profile	master	75018070-bf74-48a1-a94a-460676e3f6b8	0	10	f	\N	a001b595-588f-47a4-bc00-c62e1adb8475
a05dbf62-a475-40f0-8f88-1357f7ed4df9	\N	idp-create-user-if-unique	master	75018070-bf74-48a1-a94a-460676e3f6b8	2	20	f	\N	6126c9b0-9dc0-48c4-acb9-deb085bb5f28
fc979938-6aa7-43b7-9a52-25d3f0bd9fa2	\N	\N	master	75018070-bf74-48a1-a94a-460676e3f6b8	2	30	t	ca7053d8-b855-49cc-8a55-e064c6920690	\N
950447a4-0640-48aa-ad5c-79e301ac146a	\N	idp-confirm-link	master	ca7053d8-b855-49cc-8a55-e064c6920690	0	10	f	\N	\N
ca804aa4-3a62-4dae-aa06-21e38bc8766b	\N	idp-email-verification	master	ca7053d8-b855-49cc-8a55-e064c6920690	2	20	f	\N	\N
39e21fb7-c7f6-48b8-9ad5-be821d6087d7	\N	\N	master	ca7053d8-b855-49cc-8a55-e064c6920690	2	30	t	b67a9e18-5b62-42ec-8e6e-02fed512913a	\N
3aa68642-8f74-41b4-844f-163cf30012b3	\N	idp-username-password-form	master	b67a9e18-5b62-42ec-8e6e-02fed512913a	0	10	f	\N	\N
ee7b939f-e74f-4def-bf80-af50426215c0	\N	auth-otp-form	master	b67a9e18-5b62-42ec-8e6e-02fed512913a	1	20	f	\N	\N
eb27ff55-6ad9-481f-8995-29943d72a48b	\N	http-basic-authenticator	master	e0a70aa9-7392-447c-ab34-ec887eaa5d47	0	10	f	\N	\N
6693048d-cd1c-4796-a8fb-7c0a27f5393f	\N	docker-http-basic-authenticator	master	55bfe350-e249-48eb-ad87-114b1b1481c0	0	10	f	\N	\N
6d646577-794d-42c9-b02c-a5765858494d	\N	no-cookie-redirect	master	1054a1a5-f275-4b28-8aec-6ec6b4e6266f	0	10	f	\N	\N
60f783aa-9a5e-4c1c-9eb0-56ff457bf379	\N	basic-auth	master	1054a1a5-f275-4b28-8aec-6ec6b4e6266f	0	20	f	\N	\N
4de307ba-7969-4703-93d9-05b21c3a98a9	\N	basic-auth-otp	master	1054a1a5-f275-4b28-8aec-6ec6b4e6266f	3	30	f	\N	\N
221d09e6-d59e-4875-bcce-da5842e3f45d	\N	auth-spnego	master	1054a1a5-f275-4b28-8aec-6ec6b4e6266f	3	40	f	\N	\N
\.


--
-- Data for Name: authentication_flow; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authentication_flow (id, alias, description, realm_id, provider_id, top_level, built_in) FROM stdin;
114581d0-6ef9-4a6a-b6ce-6ec08045422f	browser	browser based authentication	master	basic-flow	t	t
a7b5f447-cd97-41f9-894e-de15e8a277be	forms	Username, password, otp and other auth forms.	master	basic-flow	f	t
7bc696c9-3787-4c74-8fbd-6a0c3ce02b91	direct grant	OpenID Connect Resource Owner Grant	master	basic-flow	t	t
7750c1f2-7d91-410a-aedd-7c5b43c5323b	registration	registration flow	master	basic-flow	t	t
8203f674-ed43-424a-ab34-376047681471	registration form	registration form	master	form-flow	f	t
dde9f98f-3689-42f9-9fc0-d27b814237ce	reset credentials	Reset credentials for a user if they forgot their password or something	master	basic-flow	t	t
a490b6cd-f301-4792-8de0-10bdfc82f48c	clients	Base authentication for clients	master	client-flow	t	t
75018070-bf74-48a1-a94a-460676e3f6b8	first broker login	Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account	master	basic-flow	t	t
ca7053d8-b855-49cc-8a55-e064c6920690	Handle Existing Account	Handle what to do if there is existing account with same email/username like authenticated identity provider	master	basic-flow	f	t
b67a9e18-5b62-42ec-8e6e-02fed512913a	Verify Existing Account by Re-authentication	Reauthentication of existing account	master	basic-flow	f	t
e0a70aa9-7392-447c-ab34-ec887eaa5d47	saml ecp	SAML ECP Profile Authentication Flow	master	basic-flow	t	t
55bfe350-e249-48eb-ad87-114b1b1481c0	docker auth	Used by Docker clients to authenticate against the IDP	master	basic-flow	t	t
1054a1a5-f275-4b28-8aec-6ec6b4e6266f	http challenge	An authentication flow based on challenge-response HTTP Authentication Schemes	master	basic-flow	t	t
\.


--
-- Data for Name: authenticator_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authenticator_config (id, alias, realm_id) FROM stdin;
a001b595-588f-47a4-bc00-c62e1adb8475	review profile config	master
6126c9b0-9dc0-48c4-acb9-deb085bb5f28	create unique user config	master
\.


--
-- Data for Name: authenticator_config_entry; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authenticator_config_entry (authenticator_id, value, name) FROM stdin;
a001b595-588f-47a4-bc00-c62e1adb8475	missing	update.profile.on.first.login
6126c9b0-9dc0-48c4-acb9-deb085bb5f28	false	require.password.update.after.registration
\.


--
-- Data for Name: broker_link; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.broker_link (identity_provider, storage_provider_id, realm_id, broker_user_id, broker_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: client; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client (id, enabled, full_scope_allowed, client_id, not_before, public_client, secret, base_url, bearer_only, management_url, surrogate_auth_required, realm_id, protocol, node_rereg_timeout, frontchannel_logout, consent_required, name, service_accounts_enabled, client_authenticator_type, root_url, description, registration_token, standard_flow_enabled, implicit_flow_enabled, direct_access_grants_enabled) FROM stdin;
31f12df6-585a-4c33-85be-57a0e11589a5	t	t	master-realm	0	f	fe76548c-73e4-4d7e-b788-4d9b3776ad5b	\N	t	\N	f	master	\N	0	f	f	master Realm	f	client-secret	\N	\N	\N	t	f	f
a36896c5-9de3-420b-aed0-cd2d3c7f746b	t	f	account	0	f	461c4fc7-a670-4ec4-b7c1-214ef07d6157	/auth/realms/master/account	f	\N	f	master	openid-connect	0	f	f	${client_account}	f	client-secret	\N	\N	\N	t	f	f
38356156-11d0-4ecb-973b-da58a497e4c1	t	f	broker	0	f	a5da3820-5880-4102-a5af-24131ea0024a	\N	f	\N	f	master	openid-connect	0	f	f	${client_broker}	f	client-secret	\N	\N	\N	t	f	f
8006cce4-48e0-4caa-9192-cdbea13985ab	t	f	security-admin-console	0	t	1318f80b-6267-4ff7-b4d8-80e4179f9c55	/auth/admin/master/console/index.html	f	\N	f	master	openid-connect	0	f	f	${client_security-admin-console}	f	client-secret	\N	\N	\N	t	f	f
db706548-197c-4474-b9a6-735588428973	t	f	admin-cli	0	t	84779151-8f04-4508-8d73-357eadc7831f	\N	f	\N	f	master	openid-connect	0	f	f	${client_admin-cli}	f	client-secret	\N	\N	\N	f	f	t
b361b54a-44b9-482c-b323-c25841bad11c	t	t	app-flaminem	0	f	18ebae53-7853-4e17-9042-2d7a75d68870	\N	f	http://app-flaminem.localtest.me:6092	f	master	openid-connect	-1	f	f	Same flaminem app	f	client-secret	http://app-flaminem.localtest.me:6092	Sample flaminem app to demonstrate role update through identity federations	\N	t	f	t
\.


--
-- Data for Name: client_attributes; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_attributes (client_id, value, name) FROM stdin;
b361b54a-44b9-482c-b323-c25841bad11c	false	saml.server.signature
b361b54a-44b9-482c-b323-c25841bad11c	false	saml.server.signature.keyinfo.ext
b361b54a-44b9-482c-b323-c25841bad11c	false	saml.assertion.signature
b361b54a-44b9-482c-b323-c25841bad11c	false	saml.client.signature
b361b54a-44b9-482c-b323-c25841bad11c	false	saml.encrypt
b361b54a-44b9-482c-b323-c25841bad11c	false	saml.authnstatement
b361b54a-44b9-482c-b323-c25841bad11c	false	saml.onetimeuse.condition
b361b54a-44b9-482c-b323-c25841bad11c	false	saml_force_name_id_format
b361b54a-44b9-482c-b323-c25841bad11c	false	saml.multivalued.roles
b361b54a-44b9-482c-b323-c25841bad11c	false	saml.force.post.binding
b361b54a-44b9-482c-b323-c25841bad11c	false	exclude.session.state.from.auth.response
b361b54a-44b9-482c-b323-c25841bad11c	false	tls.client.certificate.bound.access.tokens
b361b54a-44b9-482c-b323-c25841bad11c	false	display.on.consent.screen
\.


--
-- Data for Name: client_auth_flow_bindings; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_auth_flow_bindings (client_id, flow_id, binding_name) FROM stdin;
\.


--
-- Data for Name: client_default_roles; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_default_roles (client_id, role_id) FROM stdin;
a36896c5-9de3-420b-aed0-cd2d3c7f746b	56a85ca2-8273-4ec2-b49d-d991066a42af
a36896c5-9de3-420b-aed0-cd2d3c7f746b	762e168b-8230-47c9-a927-b7d367aa86cc
\.


--
-- Data for Name: client_initial_access; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_initial_access (id, realm_id, "timestamp", expiration, count, remaining_count) FROM stdin;
\.


--
-- Data for Name: client_node_registrations; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_node_registrations (client_id, value, name) FROM stdin;
\.


--
-- Data for Name: client_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope (id, name, realm_id, description, protocol) FROM stdin;
7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	offline_access	master	OpenID Connect built-in scope: offline_access	openid-connect
43609c01-688c-4094-b586-5cc59fe2eda8	role_list	master	SAML role list	saml
b8c68721-3d5d-4eb1-b159-c1b10444354f	profile	master	OpenID Connect built-in scope: profile	openid-connect
6636c59b-3a86-4336-91ab-5f1346fc2b37	email	master	OpenID Connect built-in scope: email	openid-connect
ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	address	master	OpenID Connect built-in scope: address	openid-connect
8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	phone	master	OpenID Connect built-in scope: phone	openid-connect
0daba024-223b-4988-b5fc-7679fd97b9d1	roles	master	OpenID Connect scope for add user roles to the access token	openid-connect
a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa	web-origins	master	OpenID Connect scope for add allowed web origins to the access token	openid-connect
51575d93-45e6-4b35-bf4a-37e4a2541c0e	microprofile-jwt	master	Microprofile - JWT built-in scope	openid-connect
\.


--
-- Data for Name: client_scope_attributes; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope_attributes (scope_id, value, name) FROM stdin;
7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	true	display.on.consent.screen
7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	${offlineAccessScopeConsentText}	consent.screen.text
43609c01-688c-4094-b586-5cc59fe2eda8	true	display.on.consent.screen
43609c01-688c-4094-b586-5cc59fe2eda8	${samlRoleListScopeConsentText}	consent.screen.text
b8c68721-3d5d-4eb1-b159-c1b10444354f	true	display.on.consent.screen
b8c68721-3d5d-4eb1-b159-c1b10444354f	${profileScopeConsentText}	consent.screen.text
b8c68721-3d5d-4eb1-b159-c1b10444354f	true	include.in.token.scope
6636c59b-3a86-4336-91ab-5f1346fc2b37	true	display.on.consent.screen
6636c59b-3a86-4336-91ab-5f1346fc2b37	${emailScopeConsentText}	consent.screen.text
6636c59b-3a86-4336-91ab-5f1346fc2b37	true	include.in.token.scope
ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	true	display.on.consent.screen
ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	${addressScopeConsentText}	consent.screen.text
ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	true	include.in.token.scope
8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	true	display.on.consent.screen
8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	${phoneScopeConsentText}	consent.screen.text
8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	true	include.in.token.scope
0daba024-223b-4988-b5fc-7679fd97b9d1	true	display.on.consent.screen
0daba024-223b-4988-b5fc-7679fd97b9d1	${rolesScopeConsentText}	consent.screen.text
0daba024-223b-4988-b5fc-7679fd97b9d1	false	include.in.token.scope
a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa	false	display.on.consent.screen
a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa		consent.screen.text
a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa	false	include.in.token.scope
51575d93-45e6-4b35-bf4a-37e4a2541c0e	false	display.on.consent.screen
51575d93-45e6-4b35-bf4a-37e4a2541c0e	true	include.in.token.scope
\.


--
-- Data for Name: client_scope_client; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope_client (client_id, scope_id, default_scope) FROM stdin;
a36896c5-9de3-420b-aed0-cd2d3c7f746b	43609c01-688c-4094-b586-5cc59fe2eda8	t
db706548-197c-4474-b9a6-735588428973	43609c01-688c-4094-b586-5cc59fe2eda8	t
38356156-11d0-4ecb-973b-da58a497e4c1	43609c01-688c-4094-b586-5cc59fe2eda8	t
31f12df6-585a-4c33-85be-57a0e11589a5	43609c01-688c-4094-b586-5cc59fe2eda8	t
8006cce4-48e0-4caa-9192-cdbea13985ab	43609c01-688c-4094-b586-5cc59fe2eda8	t
a36896c5-9de3-420b-aed0-cd2d3c7f746b	b8c68721-3d5d-4eb1-b159-c1b10444354f	t
a36896c5-9de3-420b-aed0-cd2d3c7f746b	6636c59b-3a86-4336-91ab-5f1346fc2b37	t
a36896c5-9de3-420b-aed0-cd2d3c7f746b	0daba024-223b-4988-b5fc-7679fd97b9d1	t
a36896c5-9de3-420b-aed0-cd2d3c7f746b	a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa	t
a36896c5-9de3-420b-aed0-cd2d3c7f746b	7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	f
a36896c5-9de3-420b-aed0-cd2d3c7f746b	ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	f
a36896c5-9de3-420b-aed0-cd2d3c7f746b	8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	f
a36896c5-9de3-420b-aed0-cd2d3c7f746b	51575d93-45e6-4b35-bf4a-37e4a2541c0e	f
db706548-197c-4474-b9a6-735588428973	b8c68721-3d5d-4eb1-b159-c1b10444354f	t
db706548-197c-4474-b9a6-735588428973	6636c59b-3a86-4336-91ab-5f1346fc2b37	t
db706548-197c-4474-b9a6-735588428973	0daba024-223b-4988-b5fc-7679fd97b9d1	t
db706548-197c-4474-b9a6-735588428973	a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa	t
db706548-197c-4474-b9a6-735588428973	7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	f
db706548-197c-4474-b9a6-735588428973	ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	f
db706548-197c-4474-b9a6-735588428973	8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	f
db706548-197c-4474-b9a6-735588428973	51575d93-45e6-4b35-bf4a-37e4a2541c0e	f
38356156-11d0-4ecb-973b-da58a497e4c1	b8c68721-3d5d-4eb1-b159-c1b10444354f	t
38356156-11d0-4ecb-973b-da58a497e4c1	6636c59b-3a86-4336-91ab-5f1346fc2b37	t
38356156-11d0-4ecb-973b-da58a497e4c1	0daba024-223b-4988-b5fc-7679fd97b9d1	t
38356156-11d0-4ecb-973b-da58a497e4c1	a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa	t
38356156-11d0-4ecb-973b-da58a497e4c1	7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	f
38356156-11d0-4ecb-973b-da58a497e4c1	ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	f
38356156-11d0-4ecb-973b-da58a497e4c1	8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	f
38356156-11d0-4ecb-973b-da58a497e4c1	51575d93-45e6-4b35-bf4a-37e4a2541c0e	f
31f12df6-585a-4c33-85be-57a0e11589a5	b8c68721-3d5d-4eb1-b159-c1b10444354f	t
31f12df6-585a-4c33-85be-57a0e11589a5	6636c59b-3a86-4336-91ab-5f1346fc2b37	t
31f12df6-585a-4c33-85be-57a0e11589a5	0daba024-223b-4988-b5fc-7679fd97b9d1	t
31f12df6-585a-4c33-85be-57a0e11589a5	a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa	t
31f12df6-585a-4c33-85be-57a0e11589a5	7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	f
31f12df6-585a-4c33-85be-57a0e11589a5	ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	f
31f12df6-585a-4c33-85be-57a0e11589a5	8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	f
31f12df6-585a-4c33-85be-57a0e11589a5	51575d93-45e6-4b35-bf4a-37e4a2541c0e	f
8006cce4-48e0-4caa-9192-cdbea13985ab	b8c68721-3d5d-4eb1-b159-c1b10444354f	t
8006cce4-48e0-4caa-9192-cdbea13985ab	6636c59b-3a86-4336-91ab-5f1346fc2b37	t
8006cce4-48e0-4caa-9192-cdbea13985ab	0daba024-223b-4988-b5fc-7679fd97b9d1	t
8006cce4-48e0-4caa-9192-cdbea13985ab	a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa	t
8006cce4-48e0-4caa-9192-cdbea13985ab	7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	f
8006cce4-48e0-4caa-9192-cdbea13985ab	ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	f
8006cce4-48e0-4caa-9192-cdbea13985ab	8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	f
8006cce4-48e0-4caa-9192-cdbea13985ab	51575d93-45e6-4b35-bf4a-37e4a2541c0e	f
b361b54a-44b9-482c-b323-c25841bad11c	43609c01-688c-4094-b586-5cc59fe2eda8	t
b361b54a-44b9-482c-b323-c25841bad11c	b8c68721-3d5d-4eb1-b159-c1b10444354f	t
b361b54a-44b9-482c-b323-c25841bad11c	6636c59b-3a86-4336-91ab-5f1346fc2b37	t
b361b54a-44b9-482c-b323-c25841bad11c	0daba024-223b-4988-b5fc-7679fd97b9d1	t
b361b54a-44b9-482c-b323-c25841bad11c	a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa	t
b361b54a-44b9-482c-b323-c25841bad11c	7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	f
b361b54a-44b9-482c-b323-c25841bad11c	ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	f
b361b54a-44b9-482c-b323-c25841bad11c	8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	f
b361b54a-44b9-482c-b323-c25841bad11c	51575d93-45e6-4b35-bf4a-37e4a2541c0e	f
\.


--
-- Data for Name: client_scope_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope_role_mapping (scope_id, role_id) FROM stdin;
7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	af0cc155-6222-4a13-b495-a428a79397f2
\.


--
-- Data for Name: client_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session (id, client_id, redirect_uri, state, "timestamp", session_id, auth_method, realm_id, auth_user_id, current_action) FROM stdin;
\.


--
-- Data for Name: client_session_auth_status; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_auth_status (authenticator, status, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_note; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_note (name, value, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_prot_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_prot_mapper (protocol_mapper_id, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_role; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_role (role_id, client_session) FROM stdin;
\.


--
-- Data for Name: client_user_session_note; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_user_session_note (name, value, client_session) FROM stdin;
\.


--
-- Data for Name: component; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.component (id, name, parent_id, provider_id, provider_type, realm_id, sub_type) FROM stdin;
b4fdfdce-31bd-4986-bc2d-2c18a533448a	Trusted Hosts	master	trusted-hosts	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
e802281e-b35a-4e79-a6a7-815e162a06fe	Consent Required	master	consent-required	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
ca67128d-de21-4856-8a23-3a440919bc73	Full Scope Disabled	master	scope	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
9b8bbb40-185f-4fa8-b3dd-feb7635f268c	Max Clients Limit	master	max-clients	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
734a4f37-cc90-4b54-8285-30343fdd3be0	Allowed Protocol Mapper Types	master	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
3ee78383-11b6-4409-89e3-8ef34f54381f	Allowed Client Scopes	master	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
03b901cb-785f-4185-acc3-beaf261489ea	Allowed Protocol Mapper Types	master	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	authenticated
8b2fdc21-2c61-4836-a51c-cc0b987ea3e0	Allowed Client Scopes	master	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	authenticated
5b181a61-b11e-4cde-abad-04f21169ee60	rsa-generated	master	rsa-generated	org.keycloak.keys.KeyProvider	master	\N
c8928a32-cc60-40ef-838e-0384aaee734c	hmac-generated	master	hmac-generated	org.keycloak.keys.KeyProvider	master	\N
be7ee97a-b959-4563-9410-1ccccd2a4d82	aes-generated	master	aes-generated	org.keycloak.keys.KeyProvider	master	\N
\.


--
-- Data for Name: component_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.component_config (id, component_id, name, value) FROM stdin;
dc5f744f-8e6d-4bdb-b2a4-8ce687822500	9b8bbb40-185f-4fa8-b3dd-feb7635f268c	max-clients	200
d9c16704-ed68-4e22-a29f-93ab66fe62b7	8b2fdc21-2c61-4836-a51c-cc0b987ea3e0	allow-default-scopes	true
f19f399b-2dd9-4d1b-8380-29591f97e3e4	03b901cb-785f-4185-acc3-beaf261489ea	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
aad879fd-2543-4932-b325-db0825a87a9e	03b901cb-785f-4185-acc3-beaf261489ea	allowed-protocol-mapper-types	oidc-address-mapper
c3145748-4d2b-4ed3-990d-a85e8c7f958f	03b901cb-785f-4185-acc3-beaf261489ea	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
2d90927c-6574-4253-8c06-175c64feeb49	03b901cb-785f-4185-acc3-beaf261489ea	allowed-protocol-mapper-types	saml-role-list-mapper
ce7233fa-8c66-4a18-9898-24f60d5dff5d	03b901cb-785f-4185-acc3-beaf261489ea	allowed-protocol-mapper-types	oidc-full-name-mapper
e9df02f3-29bc-44d2-8f52-69758d704833	03b901cb-785f-4185-acc3-beaf261489ea	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
2db353c9-027c-45f7-bac6-1c3bd50a3154	03b901cb-785f-4185-acc3-beaf261489ea	allowed-protocol-mapper-types	saml-user-attribute-mapper
689fdcc4-11ee-4ec7-b2df-9d3dabcbcc6d	03b901cb-785f-4185-acc3-beaf261489ea	allowed-protocol-mapper-types	saml-user-property-mapper
79259850-4620-4221-a1b7-b9579a6727c2	734a4f37-cc90-4b54-8285-30343fdd3be0	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
188d3129-45b7-4114-a94f-af0f6734bae7	734a4f37-cc90-4b54-8285-30343fdd3be0	allowed-protocol-mapper-types	oidc-full-name-mapper
6cf37e5d-31ff-4f70-b310-5347357f09ba	734a4f37-cc90-4b54-8285-30343fdd3be0	allowed-protocol-mapper-types	oidc-address-mapper
3bac3ca0-501d-4629-88e5-2d6937f46c5d	734a4f37-cc90-4b54-8285-30343fdd3be0	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
f3672631-6728-47db-be92-475079eda0cd	734a4f37-cc90-4b54-8285-30343fdd3be0	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
14cc8461-f4c0-467e-88cb-a918fa8a085b	734a4f37-cc90-4b54-8285-30343fdd3be0	allowed-protocol-mapper-types	saml-user-attribute-mapper
018173f2-5d3e-4438-a05f-9f1381360982	734a4f37-cc90-4b54-8285-30343fdd3be0	allowed-protocol-mapper-types	saml-user-property-mapper
5222615c-c176-4db8-9d9e-86843440466b	734a4f37-cc90-4b54-8285-30343fdd3be0	allowed-protocol-mapper-types	saml-role-list-mapper
03dea5c3-932f-4cd1-9532-2a815eb53047	3ee78383-11b6-4409-89e3-8ef34f54381f	allow-default-scopes	true
b97b9cf1-b233-4652-816b-e43c252b6283	b4fdfdce-31bd-4986-bc2d-2c18a533448a	host-sending-registration-request-must-match	true
bfe36ccc-a9e6-40b3-8a13-6022298877fc	b4fdfdce-31bd-4986-bc2d-2c18a533448a	client-uris-must-match	true
70865f0e-b633-4b71-96a3-c6315ada8508	c8928a32-cc60-40ef-838e-0384aaee734c	priority	100
0521d739-99d8-4243-9034-b8a8a05f11dd	c8928a32-cc60-40ef-838e-0384aaee734c	algorithm	HS256
aaf36df9-1e4a-4015-ab98-6ba1a0b280e2	c8928a32-cc60-40ef-838e-0384aaee734c	kid	2134757d-8a6c-4412-8ed9-4292045d140b
48be39f8-9220-4c0b-8620-0c670d42004d	c8928a32-cc60-40ef-838e-0384aaee734c	secret	9T6lLLcbdBEo36Dd39Hm0Om7LKDKV5xZl_7fX-4Vpk9YFvWvZH95Ry4MwunyMlzX--fAnHFnPs9c1JCtQEWMCw
720d06c4-4dbb-4aa6-9755-c04e092a052e	be7ee97a-b959-4563-9410-1ccccd2a4d82	priority	100
7abc7361-67f7-4d01-9d2f-b225fa476234	be7ee97a-b959-4563-9410-1ccccd2a4d82	kid	630dd603-4f09-4330-94ec-515ba597a8f4
326cc85d-318e-46c2-933a-bbbf656e8b19	be7ee97a-b959-4563-9410-1ccccd2a4d82	secret	QvlNDGQfbC0Z5c79wBDE1g
821792cc-f7a2-4a3d-a935-d216a3ff4680	5b181a61-b11e-4cde-abad-04f21169ee60	privateKey	MIIEpAIBAAKCAQEAhBFh2B1yb3cCTdU02QLKqhAIfhoewrW0gQnTLTxsZYBBYt0EAJ67cXZd8CJsOVoTu5zv6bqhzM9x+1s5982TT0FqfIU4HtfrOlFUmOHwNljAELfBsoJ4lexrsyc9zfUoLKb+ERx3iOxwArnS6+sTFMO65NnN7kAnlPnwsGuAuoqtLU6fxXNswZJnKWg0L3RSGmhsnX7Xb8zb6BC3uiUOp4EWx2or9Ur21B//+vAlINolFAi6/6ePZggxcGTK1KOldgaHbPGsrIYH857t8eA0k+7Ltx20i3qsZnf07yCcyYn+3V74teCUFp1j2UjH+8hZydtbMWt7jKF+W2u//qxoWwIDAQABAoIBADpJYaF7/ZFsOLwZKOXN8Zv0z4q4BHNytmNs7qK8VCrH3BPB745Gf/unffYJezIkqyjWLpw9HkPCGlARBxhyxlzoRhMGyKn0KYDnfCqtLNMPgFTghMBADPA+E5pR61kGpeBvIxpyMd9gWl8ZnBk6+oTjjYyLA/PupIl/ddam2314LF7TPtTblAcgio+5BpEpdOHVGcoFVLODVEc0USb6OYNt7xXXuUEAM5i6D2wldNAJupt4YE4FCf+c/a6fNoV/3dnEFZh978JcXm0C2dEDpomCCF5oeUneOdQ9F1XDfnRiehW7GmSUqACUG4DNYwiw54q5mmy5NpIOYUT5Vy+nZsECgYEAv21iZDQYwZSE3nDP3Xja6i9Do4+SAE5+0U+hC2d2QFs7N2DX2/gzM7AexcpiDI2cZRAfOoifKKFAih3w9D9Pp+++0Vj/owRQIlWx7X4tNOyyYIBhYAV4bz+vm+Pho0EMOQk8Z4mk+4qyN0ZXQ0KSTY8FgA2+XlFn0dTRRByHoGMCgYEAsJ4Lnt9lkKKWEah0dIDbaie8fbls+b8z2EzzlP+h8z6BikIU2g3ujDjgwuWiX52ystWvRAK4vob5mI/5puOVUJnpZyjEQl7Ih5wAsj9lVAI3jU2ZP5RZ72JpOTD176giKbwD1gjfnQglsdvUoYXyrG6nyU+dXbT33ZCZdLAPjakCgYEAkglTz5gC7uNr/frYSWBiude25TepLXy0uN/jvzx99Rjkcxn5c4HFJgCNaV09MdBy6JLFEDWcHjXuc6/l25/VGAwJadJYq7elnpv7sm/Y8xBEAOTP5J4nw881HFtcDtyYA4ctQtu6NoAX9509Az3tOSgMDSXu/itiZazSvQB643sCgYBH7MTsuStCYIPewwxR2ZwBOhdv19CCUJRLdOMJfaU1SvI0HL8jIeNQpWUa2atrZuw8GftbJgSYSp1gvNk9VpcbEOLVSOvL34+ociZycJDSSmjXGY/cLY0GiLwzNzYgmAb5mgCx7EEsUQIQ0WZhNQxjnlikCdEbNTRvvZBQzdY3qQKBgQCcW+rOSqp1LTQuivEK+R1RTg9Q/vD416TAI9Q1t4y2QAoW9RB+NBDrmNxsLsUGUzHvb08ijpxb5mL8TarrKeZLek3br/YJNLu4a+KSpqRyHx/P3WzgE4kfA8qKtY4czL0ECPs8SI9HAQmpeLmGe2fvNYf4NA8QH/iLa5RWxyyHuA==
7808eb2b-c5d6-421b-8d8f-8d908643c148	5b181a61-b11e-4cde-abad-04f21169ee60	priority	100
b09f0090-6553-4719-8683-2caa2947282b	5b181a61-b11e-4cde-abad-04f21169ee60	certificate	MIICmzCCAYMCBgFtBmf5OTANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMTkwOTA2MTE0NzIwWhcNMjkwOTA2MTE0OTAwWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCEEWHYHXJvdwJN1TTZAsqqEAh+Gh7CtbSBCdMtPGxlgEFi3QQAnrtxdl3wImw5WhO7nO/puqHMz3H7Wzn3zZNPQWp8hTge1+s6UVSY4fA2WMAQt8GygniV7GuzJz3N9Sgspv4RHHeI7HACudLr6xMUw7rk2c3uQCeU+fCwa4C6iq0tTp/Fc2zBkmcpaDQvdFIaaGydftdvzNvoELe6JQ6ngRbHaiv1SvbUH//68CUg2iUUCLr/p49mCDFwZMrUo6V2Bods8ayshgfznu3x4DST7su3HbSLeqxmd/TvIJzJif7dXvi14JQWnWPZSMf7yFnJ21sxa3uMoX5ba7/+rGhbAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHjddXjIqeOe4ME/PKrElG/s1/AHykjgZkJ2tla9Nucs+UAaAorB2ZnI+6wE8O8Oqex8iwtT8RHvwuJOHXtCChmZ4z9p/caflWUkBhO8/zhwe+0H3E70SddUT6NG39BW151Lu/gu6lZqk6f6XTsTKsY1eMqJgjvGN/X0U+B1jfFdfbYbgBttC8JdEay8OvIBFApe+XVoWN6CrCWF+Ziky+RKuGA+0DOyJZoe7DexTdPyVH6W25e6Ib+2qhAof47xwyeB9RwBdTX00y1uJRxkyxtQ6waU022kSjZHmJ72ZIMR7bhCIHRAh0WzkSEGg0N9FaFYVzCFCG+Oo0Ns4DfiGcE=
\.


--
-- Data for Name: composite_role; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.composite_role (composite, child_role) FROM stdin;
b94dfea8-e155-43df-baf0-442311859ac7	6bc397ca-e1c7-4f6a-9480-d6b19bfc07ab
b94dfea8-e155-43df-baf0-442311859ac7	f14887c7-e99b-4fa6-8514-3ed8bbbb2b42
b94dfea8-e155-43df-baf0-442311859ac7	44f47b4e-474e-4201-9dc6-9d9f0ef91b66
b94dfea8-e155-43df-baf0-442311859ac7	9aa8e5d1-583a-48ce-a2f3-f7f8cd2cb793
b94dfea8-e155-43df-baf0-442311859ac7	5ebe8617-8556-401a-8672-0b51a4f2c270
b94dfea8-e155-43df-baf0-442311859ac7	671c218a-accb-4a4b-b41b-5030518ec6d7
b94dfea8-e155-43df-baf0-442311859ac7	0f900be4-2af7-4e3b-8293-67310abe273f
b94dfea8-e155-43df-baf0-442311859ac7	886760f9-9a4c-47ff-b5aa-d7ba3bb6dd83
b94dfea8-e155-43df-baf0-442311859ac7	f780bbe4-22b0-466d-828c-3c4d0caacfd7
b94dfea8-e155-43df-baf0-442311859ac7	5fa022f1-991f-4311-a723-20e846373e0b
b94dfea8-e155-43df-baf0-442311859ac7	d03a9ed0-3eb7-4e57-903f-1da8ef6eef8f
b94dfea8-e155-43df-baf0-442311859ac7	143c1505-6c31-4e2f-902b-f14e974219a6
b94dfea8-e155-43df-baf0-442311859ac7	728edfb1-a757-4658-97a2-5ca682c37d5e
b94dfea8-e155-43df-baf0-442311859ac7	eb268a80-df95-4c7d-bb17-77f9c5444771
b94dfea8-e155-43df-baf0-442311859ac7	f86a1799-b3c0-45ec-a552-915473a63f7c
b94dfea8-e155-43df-baf0-442311859ac7	309a66ba-d293-4e01-9984-2654aee07358
b94dfea8-e155-43df-baf0-442311859ac7	d8f39eb6-e518-4a19-94b5-33948611bce8
b94dfea8-e155-43df-baf0-442311859ac7	5aa391c9-199c-4ddf-add0-00068ffdf2ba
9aa8e5d1-583a-48ce-a2f3-f7f8cd2cb793	f86a1799-b3c0-45ec-a552-915473a63f7c
9aa8e5d1-583a-48ce-a2f3-f7f8cd2cb793	5aa391c9-199c-4ddf-add0-00068ffdf2ba
5ebe8617-8556-401a-8672-0b51a4f2c270	309a66ba-d293-4e01-9984-2654aee07358
762e168b-8230-47c9-a927-b7d367aa86cc	73fb2ce8-287d-43cb-84e7-6c48c1040e3f
b94dfea8-e155-43df-baf0-442311859ac7	32a21244-5206-4f8e-acf6-4b5db1038ed7
\.


--
-- Data for Name: credential; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.credential (id, device, hash_iterations, salt, type, value, user_id, created_date, counter, digits, period, algorithm) FROM stdin;
6a6195e9-49b9-49bb-a301-350f482bbf1e	\N	27500	\\x79f083c4799df2b2f03cd6a0d846f19b	password	qsOb3TkrJY3hSuj7iZvCtOd7hBzUnBnxVwcQvx9fVmMOzYNzI8S111HzH89VnOOVpbsmCXZKYyKnYneQbxas2Q==	b0f34c1d-10c5-41f1-a22d-a56833163617	\N	0	0	0	pbkdf2-sha256
\.


--
-- Data for Name: credential_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.credential_attribute (id, credential_id, name, value) FROM stdin;
\.


--
-- Data for Name: databasechangelog; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, md5sum, description, comments, tag, liquibase, contexts, labels, deployment_id) FROM stdin;
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/jpa-changelog-1.0.0.Final.xml	2019-09-06 11:48:52.934889	1	EXECUTED	7:4e70412f24a3f382c82183742ec79317	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	3.5.4	\N	\N	7770532590
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/db2-jpa-changelog-1.0.0.Final.xml	2019-09-06 11:48:52.949388	2	MARK_RAN	7:cb16724583e9675711801c6875114f28	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	3.5.4	\N	\N	7770532590
1.1.0.Beta1	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Beta1.xml	2019-09-06 11:48:53.010363	3	EXECUTED	7:0310eb8ba07cec616460794d42ade0fa	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=CLIENT_ATTRIBUTES; createTable tableName=CLIENT_SESSION_NOTE; createTable tableName=APP_NODE_REGISTRATIONS; addColumn table...		\N	3.5.4	\N	\N	7770532590
1.1.0.Final	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Final.xml	2019-09-06 11:48:53.017104	4	EXECUTED	7:5d25857e708c3233ef4439df1f93f012	renameColumn newColumnName=EVENT_TIME, oldColumnName=TIME, tableName=EVENT_ENTITY		\N	3.5.4	\N	\N	7770532590
1.2.0.Beta1	psilva@redhat.com	META-INF/jpa-changelog-1.2.0.Beta1.xml	2019-09-06 11:48:53.158546	5	EXECUTED	7:c7a54a1041d58eb3817a4a883b4d4e84	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	3.5.4	\N	\N	7770532590
1.2.0.Beta1	psilva@redhat.com	META-INF/db2-jpa-changelog-1.2.0.Beta1.xml	2019-09-06 11:48:53.172242	6	MARK_RAN	7:2e01012df20974c1c2a605ef8afe25b7	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	3.5.4	\N	\N	7770532590
1.2.0.RC1	bburke@redhat.com	META-INF/jpa-changelog-1.2.0.CR1.xml	2019-09-06 11:48:53.313013	7	EXECUTED	7:0f08df48468428e0f30ee59a8ec01a41	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	3.5.4	\N	\N	7770532590
1.2.0.RC1	bburke@redhat.com	META-INF/db2-jpa-changelog-1.2.0.CR1.xml	2019-09-06 11:48:53.321129	8	MARK_RAN	7:a77ea2ad226b345e7d689d366f185c8c	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	3.5.4	\N	\N	7770532590
1.2.0.Final	keycloak	META-INF/jpa-changelog-1.2.0.Final.xml	2019-09-06 11:48:53.328636	9	EXECUTED	7:a3377a2059aefbf3b90ebb4c4cc8e2ab	update tableName=CLIENT; update tableName=CLIENT; update tableName=CLIENT		\N	3.5.4	\N	\N	7770532590
1.3.0	bburke@redhat.com	META-INF/jpa-changelog-1.3.0.xml	2019-09-06 11:48:53.513368	10	EXECUTED	7:04c1dbedc2aa3e9756d1a1668e003451	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=ADMI...		\N	3.5.4	\N	\N	7770532590
1.4.0	bburke@redhat.com	META-INF/jpa-changelog-1.4.0.xml	2019-09-06 11:48:53.629306	11	EXECUTED	7:36ef39ed560ad07062d956db861042ba	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	7770532590
1.4.0	bburke@redhat.com	META-INF/db2-jpa-changelog-1.4.0.xml	2019-09-06 11:48:53.632481	12	MARK_RAN	7:d909180b2530479a716d3f9c9eaea3d7	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	7770532590
1.5.0	bburke@redhat.com	META-INF/jpa-changelog-1.5.0.xml	2019-09-06 11:48:53.727636	13	EXECUTED	7:cf12b04b79bea5152f165eb41f3955f6	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	7770532590
1.6.1_from15	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 11:48:53.774395	14	EXECUTED	7:7e32c8f05c755e8675764e7d5f514509	addColumn tableName=REALM; addColumn tableName=KEYCLOAK_ROLE; addColumn tableName=CLIENT; createTable tableName=OFFLINE_USER_SESSION; createTable tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_US_SES_PK2, tableName=...		\N	3.5.4	\N	\N	7770532590
1.6.1_from16-pre	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 11:48:53.77678	15	MARK_RAN	7:980ba23cc0ec39cab731ce903dd01291	delete tableName=OFFLINE_CLIENT_SESSION; delete tableName=OFFLINE_USER_SESSION		\N	3.5.4	\N	\N	7770532590
1.6.1_from16	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 11:48:53.779399	16	MARK_RAN	7:2fa220758991285312eb84f3b4ff5336	dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_US_SES_PK, tableName=OFFLINE_USER_SESSION; dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_CL_SES_PK, tableName=OFFLINE_CLIENT_SESSION; addColumn tableName=OFFLINE_USER_SESSION; update tableName=OF...		\N	3.5.4	\N	\N	7770532590
1.6.1	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 11:48:53.782077	17	EXECUTED	7:d41d8cd98f00b204e9800998ecf8427e	empty		\N	3.5.4	\N	\N	7770532590
1.7.0	bburke@redhat.com	META-INF/jpa-changelog-1.7.0.xml	2019-09-06 11:48:53.87488	18	EXECUTED	7:91ace540896df890cc00a0490ee52bbc	createTable tableName=KEYCLOAK_GROUP; createTable tableName=GROUP_ROLE_MAPPING; createTable tableName=GROUP_ATTRIBUTE; createTable tableName=USER_GROUP_MEMBERSHIP; createTable tableName=REALM_DEFAULT_GROUPS; addColumn tableName=IDENTITY_PROVIDER; ...		\N	3.5.4	\N	\N	7770532590
1.8.0	mposolda@redhat.com	META-INF/jpa-changelog-1.8.0.xml	2019-09-06 11:48:53.949808	19	EXECUTED	7:c31d1646dfa2618a9335c00e07f89f24	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	3.5.4	\N	\N	7770532590
1.8.0-2	keycloak	META-INF/jpa-changelog-1.8.0.xml	2019-09-06 11:48:53.956118	20	EXECUTED	7:df8bc21027a4f7cbbb01f6344e89ce07	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	3.5.4	\N	\N	7770532590
authz-3.4.0.CR1-resource-server-pk-change-part1	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 11:48:54.552949	45	EXECUTED	7:6a48ce645a3525488a90fbf76adf3bb3	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_RESOURCE; addColumn tableName=RESOURCE_SERVER_SCOPE		\N	3.5.4	\N	\N	7770532590
1.8.0	mposolda@redhat.com	META-INF/db2-jpa-changelog-1.8.0.xml	2019-09-06 11:48:53.959079	21	MARK_RAN	7:f987971fe6b37d963bc95fee2b27f8df	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	3.5.4	\N	\N	7770532590
1.8.0-2	keycloak	META-INF/db2-jpa-changelog-1.8.0.xml	2019-09-06 11:48:53.962266	22	MARK_RAN	7:df8bc21027a4f7cbbb01f6344e89ce07	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	3.5.4	\N	\N	7770532590
1.9.0	mposolda@redhat.com	META-INF/jpa-changelog-1.9.0.xml	2019-09-06 11:48:53.983	23	EXECUTED	7:ed2dc7f799d19ac452cbcda56c929e47	update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=REALM; update tableName=REALM; customChange; dr...		\N	3.5.4	\N	\N	7770532590
1.9.1	keycloak	META-INF/jpa-changelog-1.9.1.xml	2019-09-06 11:48:53.993418	24	EXECUTED	7:80b5db88a5dda36ece5f235be8757615	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=PUBLIC_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	3.5.4	\N	\N	7770532590
1.9.1	keycloak	META-INF/db2-jpa-changelog-1.9.1.xml	2019-09-06 11:48:53.995872	25	MARK_RAN	7:1437310ed1305a9b93f8848f301726ce	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	3.5.4	\N	\N	7770532590
1.9.2	keycloak	META-INF/jpa-changelog-1.9.2.xml	2019-09-06 11:48:54.031694	26	EXECUTED	7:b82ffb34850fa0836be16deefc6a87c4	createIndex indexName=IDX_USER_EMAIL, tableName=USER_ENTITY; createIndex indexName=IDX_USER_ROLE_MAPPING, tableName=USER_ROLE_MAPPING; createIndex indexName=IDX_USER_GROUP_MAPPING, tableName=USER_GROUP_MEMBERSHIP; createIndex indexName=IDX_USER_CO...		\N	3.5.4	\N	\N	7770532590
authz-2.0.0	psilva@redhat.com	META-INF/jpa-changelog-authz-2.0.0.xml	2019-09-06 11:48:54.09895	27	EXECUTED	7:9cc98082921330d8d9266decdd4bd658	createTable tableName=RESOURCE_SERVER; addPrimaryKey constraintName=CONSTRAINT_FARS, tableName=RESOURCE_SERVER; addUniqueConstraint constraintName=UK_AU8TT6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER; createTable tableName=RESOURCE_SERVER_RESOU...		\N	3.5.4	\N	\N	7770532590
authz-2.5.1	psilva@redhat.com	META-INF/jpa-changelog-authz-2.5.1.xml	2019-09-06 11:48:54.102426	28	EXECUTED	7:03d64aeed9cb52b969bd30a7ac0db57e	update tableName=RESOURCE_SERVER_POLICY		\N	3.5.4	\N	\N	7770532590
2.1.0-KEYCLOAK-5461	bburke@redhat.com	META-INF/jpa-changelog-2.1.0.xml	2019-09-06 11:48:54.174508	29	EXECUTED	7:f1f9fd8710399d725b780f463c6b21cd	createTable tableName=BROKER_LINK; createTable tableName=FED_USER_ATTRIBUTE; createTable tableName=FED_USER_CONSENT; createTable tableName=FED_USER_CONSENT_ROLE; createTable tableName=FED_USER_CONSENT_PROT_MAPPER; createTable tableName=FED_USER_CR...		\N	3.5.4	\N	\N	7770532590
2.2.0	bburke@redhat.com	META-INF/jpa-changelog-2.2.0.xml	2019-09-06 11:48:54.229671	30	EXECUTED	7:53188c3eb1107546e6f765835705b6c1	addColumn tableName=ADMIN_EVENT_ENTITY; createTable tableName=CREDENTIAL_ATTRIBUTE; createTable tableName=FED_CREDENTIAL_ATTRIBUTE; modifyDataType columnName=VALUE, tableName=CREDENTIAL; addForeignKeyConstraint baseTableName=FED_CREDENTIAL_ATTRIBU...		\N	3.5.4	\N	\N	7770532590
2.3.0	bburke@redhat.com	META-INF/jpa-changelog-2.3.0.xml	2019-09-06 11:48:54.258068	31	EXECUTED	7:d6e6f3bc57a0c5586737d1351725d4d4	createTable tableName=FEDERATED_USER; addPrimaryKey constraintName=CONSTR_FEDERATED_USER, tableName=FEDERATED_USER; dropDefaultValue columnName=TOTP, tableName=USER_ENTITY; dropColumn columnName=TOTP, tableName=USER_ENTITY; addColumn tableName=IDE...		\N	3.5.4	\N	\N	7770532590
2.4.0	bburke@redhat.com	META-INF/jpa-changelog-2.4.0.xml	2019-09-06 11:48:54.272266	32	EXECUTED	7:454d604fbd755d9df3fd9c6329043aa5	customChange		\N	3.5.4	\N	\N	7770532590
2.5.0	bburke@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 11:48:54.290304	33	EXECUTED	7:57e98a3077e29caf562f7dbf80c72600	customChange; modifyDataType columnName=USER_ID, tableName=OFFLINE_USER_SESSION		\N	3.5.4	\N	\N	7770532590
2.5.0-unicode-oracle	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 11:48:54.303553	34	MARK_RAN	7:e4c7e8f2256210aee71ddc42f538b57a	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	3.5.4	\N	\N	7770532590
2.5.0-unicode-other-dbs	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 11:48:54.35753	35	EXECUTED	7:09a43c97e49bc626460480aa1379b522	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	3.5.4	\N	\N	7770532590
2.5.0-duplicate-email-support	slawomir@dabek.name	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 11:48:54.378236	36	EXECUTED	7:26bfc7c74fefa9126f2ce702fb775553	addColumn tableName=REALM		\N	3.5.4	\N	\N	7770532590
2.5.0-unique-group-names	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 11:48:54.383801	37	EXECUTED	7:a161e2ae671a9020fff61e996a207377	addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	3.5.4	\N	\N	7770532590
2.5.1	bburke@redhat.com	META-INF/jpa-changelog-2.5.1.xml	2019-09-06 11:48:54.388052	38	EXECUTED	7:37fc1781855ac5388c494f1442b3f717	addColumn tableName=FED_USER_CONSENT		\N	3.5.4	\N	\N	7770532590
3.0.0	bburke@redhat.com	META-INF/jpa-changelog-3.0.0.xml	2019-09-06 11:48:54.398459	39	EXECUTED	7:13a27db0dae6049541136adad7261d27	addColumn tableName=IDENTITY_PROVIDER		\N	3.5.4	\N	\N	7770532590
3.2.0-fix	keycloak	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 11:48:54.400484	40	MARK_RAN	7:550300617e3b59e8af3a6294df8248a3	addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS		\N	3.5.4	\N	\N	7770532590
3.2.0-fix-with-keycloak-5416	keycloak	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 11:48:54.402321	41	MARK_RAN	7:e3a9482b8931481dc2772a5c07c44f17	dropIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS; addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS; createIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS		\N	3.5.4	\N	\N	7770532590
3.2.0-fix-offline-sessions	hmlnarik	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 11:48:54.409677	42	EXECUTED	7:72b07d85a2677cb257edb02b408f332d	customChange		\N	3.5.4	\N	\N	7770532590
3.2.0-fixed	keycloak	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 11:48:54.527561	43	EXECUTED	7:a72a7858967bd414835d19e04d880312	addColumn tableName=REALM; dropPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_PK2, tableName=OFFLINE_CLIENT_SESSION; dropColumn columnName=CLIENT_SESSION_ID, tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_P...		\N	3.5.4	\N	\N	7770532590
3.3.0	keycloak	META-INF/jpa-changelog-3.3.0.xml	2019-09-06 11:48:54.54588	44	EXECUTED	7:94edff7cf9ce179e7e85f0cd78a3cf2c	addColumn tableName=USER_ENTITY		\N	3.5.4	\N	\N	7770532590
authz-3.4.0.CR1-resource-server-pk-change-part2-KEYCLOAK-6095	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 11:48:54.562713	46	EXECUTED	7:e64b5dcea7db06077c6e57d3b9e5ca14	customChange		\N	3.5.4	\N	\N	7770532590
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 11:48:54.56682	47	MARK_RAN	7:fd8cf02498f8b1e72496a20afc75178c	dropIndex indexName=IDX_RES_SERV_POL_RES_SERV, tableName=RESOURCE_SERVER_POLICY; dropIndex indexName=IDX_RES_SRV_RES_RES_SRV, tableName=RESOURCE_SERVER_RESOURCE; dropIndex indexName=IDX_RES_SRV_SCOPE_RES_SRV, tableName=RESOURCE_SERVER_SCOPE		\N	3.5.4	\N	\N	7770532590
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed-nodropindex	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 11:48:54.646606	48	EXECUTED	7:542794f25aa2b1fbabb7e577d6646319	addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_POLICY; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_RESOURCE; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, ...		\N	3.5.4	\N	\N	7770532590
authn-3.4.0.CR1-refresh-token-max-reuse	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 11:48:54.676272	49	EXECUTED	7:edad604c882df12f74941dac3cc6d650	addColumn tableName=REALM		\N	3.5.4	\N	\N	7770532590
3.4.0	keycloak	META-INF/jpa-changelog-3.4.0.xml	2019-09-06 11:48:54.72133	50	EXECUTED	7:0f88b78b7b46480eb92690cbf5e44900	addPrimaryKey constraintName=CONSTRAINT_REALM_DEFAULT_ROLES, tableName=REALM_DEFAULT_ROLES; addPrimaryKey constraintName=CONSTRAINT_COMPOSITE_ROLE, tableName=COMPOSITE_ROLE; addPrimaryKey constraintName=CONSTR_REALM_DEFAULT_GROUPS, tableName=REALM...		\N	3.5.4	\N	\N	7770532590
3.4.0-KEYCLOAK-5230	hmlnarik@redhat.com	META-INF/jpa-changelog-3.4.0.xml	2019-09-06 11:48:54.751112	51	EXECUTED	7:d560e43982611d936457c327f872dd59	createIndex indexName=IDX_FU_ATTRIBUTE, tableName=FED_USER_ATTRIBUTE; createIndex indexName=IDX_FU_CONSENT, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CONSENT_RU, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CREDENTIAL, t...		\N	3.5.4	\N	\N	7770532590
3.4.1	psilva@redhat.com	META-INF/jpa-changelog-3.4.1.xml	2019-09-06 11:48:54.754543	52	EXECUTED	7:c155566c42b4d14ef07059ec3b3bbd8e	modifyDataType columnName=VALUE, tableName=CLIENT_ATTRIBUTES		\N	3.5.4	\N	\N	7770532590
3.4.2	keycloak	META-INF/jpa-changelog-3.4.2.xml	2019-09-06 11:48:54.757699	53	EXECUTED	7:b40376581f12d70f3c89ba8ddf5b7dea	update tableName=REALM		\N	3.5.4	\N	\N	7770532590
3.4.2-KEYCLOAK-5172	mkanis@redhat.com	META-INF/jpa-changelog-3.4.2.xml	2019-09-06 11:48:54.761045	54	EXECUTED	7:a1132cc395f7b95b3646146c2e38f168	update tableName=CLIENT		\N	3.5.4	\N	\N	7770532590
4.0.0-KEYCLOAK-6335	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 11:48:54.767947	55	EXECUTED	7:d8dc5d89c789105cfa7ca0e82cba60af	createTable tableName=CLIENT_AUTH_FLOW_BINDINGS; addPrimaryKey constraintName=C_CLI_FLOW_BIND, tableName=CLIENT_AUTH_FLOW_BINDINGS		\N	3.5.4	\N	\N	7770532590
4.0.0-CLEANUP-UNUSED-TABLE	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 11:48:54.772495	56	EXECUTED	7:7822e0165097182e8f653c35517656a3	dropTable tableName=CLIENT_IDENTITY_PROV_MAPPING		\N	3.5.4	\N	\N	7770532590
4.0.0-KEYCLOAK-6228	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 11:48:54.803816	57	EXECUTED	7:c6538c29b9c9a08f9e9ea2de5c2b6375	dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; dropNotNullConstraint columnName=CLIENT_ID, tableName=USER_CONSENT; addColumn tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHO...		\N	3.5.4	\N	\N	7770532590
4.0.0-KEYCLOAK-5579-fixed	mposolda@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 11:48:54.890402	58	EXECUTED	7:6d4893e36de22369cf73bcb051ded875	dropForeignKeyConstraint baseTableName=CLIENT_TEMPLATE_ATTRIBUTES, constraintName=FK_CL_TEMPL_ATTR_TEMPL; renameTable newTableName=CLIENT_SCOPE_ATTRIBUTES, oldTableName=CLIENT_TEMPLATE_ATTRIBUTES; renameColumn newColumnName=SCOPE_ID, oldColumnName...		\N	3.5.4	\N	\N	7770532590
authz-4.0.0.CR1	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.CR1.xml	2019-09-06 11:48:54.953251	59	EXECUTED	7:57960fc0b0f0dd0563ea6f8b2e4a1707	createTable tableName=RESOURCE_SERVER_PERM_TICKET; addPrimaryKey constraintName=CONSTRAINT_FAPMT, tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRHO213XCX4WNKOG82SSPMT...		\N	3.5.4	\N	\N	7770532590
authz-4.0.0.Beta3	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.Beta3.xml	2019-09-06 11:48:54.964214	60	EXECUTED	7:2b4b8bff39944c7097977cc18dbceb3b	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRPO2128CX4WNKOG82SSRFY, referencedTableName=RESOURCE_SERVER_POLICY		\N	3.5.4	\N	\N	7770532590
authz-4.2.0.Final	mhajas@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2019-09-06 11:48:54.981488	61	EXECUTED	7:2aa42a964c59cd5b8ca9822340ba33a8	createTable tableName=RESOURCE_URIS; addForeignKeyConstraint baseTableName=RESOURCE_URIS, constraintName=FK_RESOURCE_SERVER_URIS, referencedTableName=RESOURCE_SERVER_RESOURCE; customChange; dropColumn columnName=URI, tableName=RESOURCE_SERVER_RESO...		\N	3.5.4	\N	\N	7770532590
authz-4.2.0.Final-KEYCLOAK-9944	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2019-09-06 11:48:54.990249	62	EXECUTED	7:9ac9e58545479929ba23f4a3087a0346	addPrimaryKey constraintName=CONSTRAINT_RESOUR_URIS_PK, tableName=RESOURCE_URIS		\N	3.5.4	\N	\N	7770532590
4.2.0-KEYCLOAK-6313	wadahiro@gmail.com	META-INF/jpa-changelog-4.2.0.xml	2019-09-06 11:48:54.995746	63	EXECUTED	7:14d407c35bc4fe1976867756bcea0c36	addColumn tableName=REQUIRED_ACTION_PROVIDER		\N	3.5.4	\N	\N	7770532590
4.3.0-KEYCLOAK-7984	wadahiro@gmail.com	META-INF/jpa-changelog-4.3.0.xml	2019-09-06 11:48:55.002202	64	EXECUTED	7:241a8030c748c8548e346adee548fa93	update tableName=REQUIRED_ACTION_PROVIDER		\N	3.5.4	\N	\N	7770532590
4.6.0-KEYCLOAK-7950	psilva@redhat.com	META-INF/jpa-changelog-4.6.0.xml	2019-09-06 11:48:55.007112	65	EXECUTED	7:7d3182f65a34fcc61e8d23def037dc3f	update tableName=RESOURCE_SERVER_RESOURCE		\N	3.5.4	\N	\N	7770532590
4.6.0-KEYCLOAK-8377	keycloak	META-INF/jpa-changelog-4.6.0.xml	2019-09-06 11:48:55.028957	66	EXECUTED	7:b30039e00a0b9715d430d1b0636728fa	createTable tableName=ROLE_ATTRIBUTE; addPrimaryKey constraintName=CONSTRAINT_ROLE_ATTRIBUTE_PK, tableName=ROLE_ATTRIBUTE; addForeignKeyConstraint baseTableName=ROLE_ATTRIBUTE, constraintName=FK_ROLE_ATTRIBUTE_ID, referencedTableName=KEYCLOAK_ROLE...		\N	3.5.4	\N	\N	7770532590
4.6.0-KEYCLOAK-8555	gideonray@gmail.com	META-INF/jpa-changelog-4.6.0.xml	2019-09-06 11:48:55.038021	67	EXECUTED	7:3797315ca61d531780f8e6f82f258159	createIndex indexName=IDX_COMPONENT_PROVIDER_TYPE, tableName=COMPONENT		\N	3.5.4	\N	\N	7770532590
4.7.0-KEYCLOAK-1267	sguilhen@redhat.com	META-INF/jpa-changelog-4.7.0.xml	2019-09-06 11:48:55.080624	68	EXECUTED	7:c7aa4c8d9573500c2d347c1941ff0301	addColumn tableName=REALM		\N	3.5.4	\N	\N	7770532590
4.7.0-KEYCLOAK-7275	keycloak	META-INF/jpa-changelog-4.7.0.xml	2019-09-06 11:48:55.108118	69	EXECUTED	7:b207faee394fc074a442ecd42185a5dd	renameColumn newColumnName=CREATED_ON, oldColumnName=LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION; addNotNullConstraint columnName=CREATED_ON, tableName=OFFLINE_USER_SESSION; addColumn tableName=OFFLINE_USER_SESSION; customChange; createIn...		\N	3.5.4	\N	\N	7770532590
4.8.0-KEYCLOAK-8835	sguilhen@redhat.com	META-INF/jpa-changelog-4.8.0.xml	2019-09-06 11:48:55.116915	70	EXECUTED	7:ab9a9762faaba4ddfa35514b212c4922	addNotNullConstraint columnName=SSO_MAX_LIFESPAN_REMEMBER_ME, tableName=REALM; addNotNullConstraint columnName=SSO_IDLE_TIMEOUT_REMEMBER_ME, tableName=REALM		\N	3.5.4	\N	\N	7770532590
authz-7.0.0-KEYCLOAK-10443	psilva@redhat.com	META-INF/jpa-changelog-authz-7.0.0.xml	2019-09-06 11:48:55.128174	71	EXECUTED	7:b9710f74515a6ccb51b72dc0d19df8c4	addColumn tableName=RESOURCE_SERVER		\N	3.5.4	\N	\N	7770532590
\.


--
-- Data for Name: databasechangeloglock; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.databasechangeloglock (id, locked, lockgranted, lockedby) FROM stdin;
1	f	\N	\N
1000	f	\N	\N
1001	f	\N	\N
\.


--
-- Data for Name: default_client_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.default_client_scope (realm_id, scope_id, default_scope) FROM stdin;
master	7fbb1e9e-9a94-4a93-ad85-8dc2df1e13cb	f
master	43609c01-688c-4094-b586-5cc59fe2eda8	t
master	b8c68721-3d5d-4eb1-b159-c1b10444354f	t
master	6636c59b-3a86-4336-91ab-5f1346fc2b37	t
master	ffbae3cf-a1d4-4686-8efe-b1a917e77a0c	f
master	8ce8102c-9fbf-40fb-89f8-31787ca3fc6f	f
master	0daba024-223b-4988-b5fc-7679fd97b9d1	t
master	a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa	t
master	51575d93-45e6-4b35-bf4a-37e4a2541c0e	f
\.


--
-- Data for Name: event_entity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.event_entity (id, client_id, details_json, error, ip_address, realm_id, session_id, event_time, type, user_id) FROM stdin;
\.


--
-- Data for Name: fed_credential_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_credential_attribute (id, credential_id, name, value) FROM stdin;
\.


--
-- Data for Name: fed_user_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_attribute (id, name, user_id, realm_id, storage_provider_id, value) FROM stdin;
\.


--
-- Data for Name: fed_user_consent; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_consent (id, client_id, user_id, realm_id, storage_provider_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: fed_user_consent_cl_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_consent_cl_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: fed_user_credential; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_credential (id, device, hash_iterations, salt, type, value, created_date, counter, digits, period, algorithm, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_group_membership; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_group_membership (group_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_required_action; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_required_action (required_action, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_role_mapping (role_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: federated_identity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.federated_identity (identity_provider, realm_id, federated_user_id, federated_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: federated_user; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.federated_user (id, storage_provider_id, realm_id) FROM stdin;
\.


--
-- Data for Name: group_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.group_attribute (id, name, value, group_id) FROM stdin;
\.


--
-- Data for Name: group_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.group_role_mapping (role_id, group_id) FROM stdin;
\.


--
-- Data for Name: identity_provider; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.identity_provider (internal_id, enabled, provider_alias, provider_id, store_token, authenticate_by_default, realm_id, add_token_role, trust_email, first_broker_login_flow_id, post_broker_login_flow_id, provider_display_name, link_only) FROM stdin;
dd586290-0997-46f7-86a1-5091f2dc0950	t	oidc-customer	oidc	f	f	master	f	t	75018070-bf74-48a1-a94a-460676e3f6b8	\N	Standard OiDC customer	f
44465381-d2e1-440c-ba7a-93deda37f056	t	keycloak-oidc	keycloak-oidc	f	f	master	f	t	75018070-bf74-48a1-a94a-460676e3f6b8	\N	Keycloak OIDC customer	f
\.


--
-- Data for Name: identity_provider_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.identity_provider_config (identity_provider_id, value, name) FROM stdin;
44465381-d2e1-440c-ba7a-93deda37f056		hideOnLoginPage
44465381-d2e1-440c-ba7a-93deda37f056	true	validateSignature
44465381-d2e1-440c-ba7a-93deda37f056	http://keycloak-customer.localtest.me:8081/auth/realms/master/protocol/openid-connect/userinfo	userInfoUrl
44465381-d2e1-440c-ba7a-93deda37f056		uiLocales
44465381-d2e1-440c-ba7a-93deda37f056		acceptsPromptNoneForwardFromClient
44465381-d2e1-440c-ba7a-93deda37f056	http://keycloak-customer.localtest.me:8081/auth/realms/master/protocol/openid-connect/token	tokenUrl
44465381-d2e1-440c-ba7a-93deda37f056	idp-flaminem	clientId
44465381-d2e1-440c-ba7a-93deda37f056	http://keycloak-customer.localtest.me:8081/auth/realms/master/protocol/openid-connect/certs	jwksUrl
44465381-d2e1-440c-ba7a-93deda37f056		backchannelSupported
44465381-d2e1-440c-ba7a-93deda37f056	http://keycloak-customer.localtest.me:8081/auth/realms/master	issuer
44465381-d2e1-440c-ba7a-93deda37f056	true	useJwksUrl
44465381-d2e1-440c-ba7a-93deda37f056		loginHint
44465381-d2e1-440c-ba7a-93deda37f056	http://keycloak-customer.localtest.me:8081/auth/realms/master/protocol/openid-connect/auth	authorizationUrl
44465381-d2e1-440c-ba7a-93deda37f056		disableUserInfo
44465381-d2e1-440c-ba7a-93deda37f056	http://keycloak-customer.localtest.me:8081/auth/realms/master/protocol/openid-connect/logout	logoutUrl
44465381-d2e1-440c-ba7a-93deda37f056	0f5232ad-02eb-4ebf-b70a-501f23255546	clientSecret
dd586290-0997-46f7-86a1-5091f2dc0950		hideOnLoginPage
dd586290-0997-46f7-86a1-5091f2dc0950	true	validateSignature
dd586290-0997-46f7-86a1-5091f2dc0950	http://keycloak-oidc.localtest.me:8082/auth/realms/master/protocol/openid-connect/userinfo	userInfoUrl
dd586290-0997-46f7-86a1-5091f2dc0950		uiLocales
dd586290-0997-46f7-86a1-5091f2dc0950		acceptsPromptNoneForwardFromClient
dd586290-0997-46f7-86a1-5091f2dc0950	http://keycloak-oidc.localtest.me:8082/auth/realms/master/protocol/openid-connect/token	tokenUrl
dd586290-0997-46f7-86a1-5091f2dc0950	idp-flaminem	clientId
dd586290-0997-46f7-86a1-5091f2dc0950	http://keycloak-oidc.localtest.me:8082/auth/realms/master/protocol/openid-connect/certs	jwksUrl
dd586290-0997-46f7-86a1-5091f2dc0950	true	backchannelSupported
dd586290-0997-46f7-86a1-5091f2dc0950	http://keycloak-oidc.localtest.me:8082/auth/realms/master	issuer
dd586290-0997-46f7-86a1-5091f2dc0950	true	useJwksUrl
dd586290-0997-46f7-86a1-5091f2dc0950		loginHint
dd586290-0997-46f7-86a1-5091f2dc0950	http://keycloak-oidc.localtest.me:8082/auth/realms/master/protocol/openid-connect/auth	authorizationUrl
dd586290-0997-46f7-86a1-5091f2dc0950		disableUserInfo
dd586290-0997-46f7-86a1-5091f2dc0950	http://keycloak-oidc.localtest.me:8082/auth/realms/master/protocol/openid-connect/logout	logoutUrl
dd586290-0997-46f7-86a1-5091f2dc0950	93002f5f-ad3f-4cde-8ee2-06f3f3a335cb	clientSecret
\.


--
-- Data for Name: identity_provider_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.identity_provider_mapper (id, name, idp_alias, idp_mapper_name, realm_id) FROM stdin;
202baf2e-496b-4287-bf2e-8a9010c9fafe	Default role	oidc-customer	oidc-hardcoded-role-idp-mapper	master
9f5ff5ad-de75-43ec-a555-66afe7f63d49	do-something	oidc-customer	oidc-role-idp-mapper	master
5b31aa2f-d29d-439f-a5a2-26a5632b7999	do-something-else	oidc-customer	oidc-role-idp-mapper	master
bf484371-6b25-4afb-bcd1-2ead3ce03db2	Origin OIDC	oidc-customer	oidc-hardcoded-role-idp-mapper	master
548e9e3d-c5aa-408b-b69d-57ea0188a2cd	Default role	keycloak-oidc	oidc-hardcoded-role-idp-mapper	master
b6d15049-8171-4f8c-867c-995974ca7cca	do-something-else	keycloak-oidc	oidc-role-idp-mapper	master
2c71fd33-a489-4d6f-bbb6-ffc391d98621	do-something	keycloak-oidc	oidc-role-idp-mapper	master
2d10a0b9-1c0f-4787-92d0-0e73419a6c09	Keycloak Origin	keycloak-oidc	oidc-hardcoded-role-idp-mapper	master
2e599dc1-afbb-4810-9526-fd96ac53922d	External keycloak role	keycloak-oidc	keycloak-oidc-role-to-role-idp-mapper	master
\.


--
-- Data for Name: idp_mapper_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.idp_mapper_config (idp_mapper_id, value, name) FROM stdin;
202baf2e-496b-4287-bf2e-8a9010c9fafe	admin	role
9f5ff5ad-de75-43ec-a555-66afe7f63d49	groups	claim
9f5ff5ad-de75-43ec-a555-66afe7f63d49	can-do-this	role
9f5ff5ad-de75-43ec-a555-66afe7f63d49	can-do-this-flaminem	claim.value
5b31aa2f-d29d-439f-a5a2-26a5632b7999	groups	claim
5b31aa2f-d29d-439f-a5a2-26a5632b7999	can-do-that	role
5b31aa2f-d29d-439f-a5a2-26a5632b7999	can-do-that-flaminem	claim.value
bf484371-6b25-4afb-bcd1-2ead3ce03db2	from-oidc-user	role
548e9e3d-c5aa-408b-b69d-57ea0188a2cd	admin	role
b6d15049-8171-4f8c-867c-995974ca7cca	groups	claim
b6d15049-8171-4f8c-867c-995974ca7cca	can-do-that	role
b6d15049-8171-4f8c-867c-995974ca7cca	can-do-that-flaminem	claim.value
2c71fd33-a489-4d6f-bbb6-ffc391d98621	groups	claim
2c71fd33-a489-4d6f-bbb6-ffc391d98621	can-do-this	role
2c71fd33-a489-4d6f-bbb6-ffc391d98621	can-do-this-flaminem	claim.value
2d10a0b9-1c0f-4787-92d0-0e73419a6c09	from-keycloak-user	role
2e599dc1-afbb-4810-9526-fd96ac53922d	external-keycloak-role	role
2e599dc1-afbb-4810-9526-fd96ac53922d	external-keycloak-role	external.role
\.


--
-- Data for Name: keycloak_group; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.keycloak_group (id, name, parent_group, realm_id) FROM stdin;
\.


--
-- Data for Name: keycloak_role; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.keycloak_role (id, client_realm_constraint, client_role, description, name, realm_id, client, realm) FROM stdin;
b94dfea8-e155-43df-baf0-442311859ac7	master	f	${role_admin}	admin	master	\N	master
6bc397ca-e1c7-4f6a-9480-d6b19bfc07ab	master	f	${role_create-realm}	create-realm	master	\N	master
f14887c7-e99b-4fa6-8514-3ed8bbbb2b42	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_create-client}	create-client	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
44f47b4e-474e-4201-9dc6-9d9f0ef91b66	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_view-realm}	view-realm	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
9aa8e5d1-583a-48ce-a2f3-f7f8cd2cb793	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_view-users}	view-users	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
5ebe8617-8556-401a-8672-0b51a4f2c270	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_view-clients}	view-clients	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
671c218a-accb-4a4b-b41b-5030518ec6d7	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_view-events}	view-events	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
0f900be4-2af7-4e3b-8293-67310abe273f	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_view-identity-providers}	view-identity-providers	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
886760f9-9a4c-47ff-b5aa-d7ba3bb6dd83	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_view-authorization}	view-authorization	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
f780bbe4-22b0-466d-828c-3c4d0caacfd7	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_manage-realm}	manage-realm	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
5fa022f1-991f-4311-a723-20e846373e0b	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_manage-users}	manage-users	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
d03a9ed0-3eb7-4e57-903f-1da8ef6eef8f	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_manage-clients}	manage-clients	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
143c1505-6c31-4e2f-902b-f14e974219a6	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_manage-events}	manage-events	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
728edfb1-a757-4658-97a2-5ca682c37d5e	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_manage-identity-providers}	manage-identity-providers	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
eb268a80-df95-4c7d-bb17-77f9c5444771	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_manage-authorization}	manage-authorization	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
f86a1799-b3c0-45ec-a552-915473a63f7c	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_query-users}	query-users	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
309a66ba-d293-4e01-9984-2654aee07358	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_query-clients}	query-clients	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
d8f39eb6-e518-4a19-94b5-33948611bce8	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_query-realms}	query-realms	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
5aa391c9-199c-4ddf-add0-00068ffdf2ba	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_query-groups}	query-groups	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
56a85ca2-8273-4ec2-b49d-d991066a42af	a36896c5-9de3-420b-aed0-cd2d3c7f746b	t	${role_view-profile}	view-profile	master	a36896c5-9de3-420b-aed0-cd2d3c7f746b	\N
762e168b-8230-47c9-a927-b7d367aa86cc	a36896c5-9de3-420b-aed0-cd2d3c7f746b	t	${role_manage-account}	manage-account	master	a36896c5-9de3-420b-aed0-cd2d3c7f746b	\N
73fb2ce8-287d-43cb-84e7-6c48c1040e3f	a36896c5-9de3-420b-aed0-cd2d3c7f746b	t	${role_manage-account-links}	manage-account-links	master	a36896c5-9de3-420b-aed0-cd2d3c7f746b	\N
c60276ff-0da7-4607-9c43-540461e587b7	38356156-11d0-4ecb-973b-da58a497e4c1	t	${role_read-token}	read-token	master	38356156-11d0-4ecb-973b-da58a497e4c1	\N
32a21244-5206-4f8e-acf6-4b5db1038ed7	31f12df6-585a-4c33-85be-57a0e11589a5	t	${role_impersonation}	impersonation	master	31f12df6-585a-4c33-85be-57a0e11589a5	\N
af0cc155-6222-4a13-b495-a428a79397f2	master	f	${role_offline-access}	offline_access	master	\N	master
0b735fa1-f21d-4c5d-b51b-9710cc89e844	master	f	${role_uma_authorization}	uma_authorization	master	\N	master
de63c457-0c02-4bfd-8b09-de3a798d42c9	master	f	\N	from-oidc-user	master	\N	master
c2c8d886-3de5-47e1-8fe7-84c155711ee1	master	f	\N	from-keycloak-user	master	\N	master
315cda71-caa5-4aa1-97bf-14a1c5c12534	master	f	\N	can-do-this	master	\N	master
2c028f9c-fcb1-45dc-b761-9d0e4065ae39	master	f	\N	can-do-that	master	\N	master
d798bb68-4773-44a9-babe-563c3335095f	master	f	\N	external-keycloak-role	master	\N	master
\.


--
-- Data for Name: migration_model; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.migration_model (id, version) FROM stdin;
SINGLETON	6.0.0
\.


--
-- Data for Name: offline_client_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.offline_client_session (user_session_id, client_id, offline_flag, "timestamp", data, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: offline_user_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.offline_user_session (user_session_id, user_id, realm_id, created_on, offline_flag, data, last_session_refresh) FROM stdin;
\.


--
-- Data for Name: policy_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.policy_config (policy_id, name, value) FROM stdin;
\.


--
-- Data for Name: protocol_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.protocol_mapper (id, name, protocol, protocol_mapper_name, client_id, client_scope_id) FROM stdin;
8e8fcfe5-3f07-4a59-8d58-a02421a5bfda	locale	openid-connect	oidc-usermodel-attribute-mapper	8006cce4-48e0-4caa-9192-cdbea13985ab	\N
285778bd-02d2-4dc0-80db-e4aed350bbf6	role list	saml	saml-role-list-mapper	\N	43609c01-688c-4094-b586-5cc59fe2eda8
9d75d365-e1ac-4f52-b4ab-6751f6df038d	full name	openid-connect	oidc-full-name-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
55286902-cf9e-4069-8796-0f65339ccf6f	family name	openid-connect	oidc-usermodel-property-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
b432ad8d-e088-4764-9296-ecc8958036f1	given name	openid-connect	oidc-usermodel-property-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
190bff59-0263-4dae-84bc-fb59825b3e79	middle name	openid-connect	oidc-usermodel-attribute-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
38fdc4e1-f31e-44bf-a9bc-906579ef6979	nickname	openid-connect	oidc-usermodel-attribute-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
3ba8413c-6fef-4a02-b8d8-2b0b98bfdb06	username	openid-connect	oidc-usermodel-property-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
476c8852-b534-45d7-bd4c-1da783888856	profile	openid-connect	oidc-usermodel-attribute-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
65d20680-99ba-485a-9365-f7155d41bb6a	picture	openid-connect	oidc-usermodel-attribute-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
6316e814-247f-4dc1-8506-ce11254b6f11	website	openid-connect	oidc-usermodel-attribute-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
68e954d0-55f7-44a5-aaca-22a7b3bdec65	gender	openid-connect	oidc-usermodel-attribute-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
598d77be-f31f-4783-87f0-418e34fe7bfc	birthdate	openid-connect	oidc-usermodel-attribute-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
1ecb75b1-90d6-4eea-8bba-33e29e4637d2	zoneinfo	openid-connect	oidc-usermodel-attribute-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
be28faac-473a-4403-bad8-955a126d999f	locale	openid-connect	oidc-usermodel-attribute-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
46beb4f4-8146-4886-81c2-e92b2b29a419	updated at	openid-connect	oidc-usermodel-attribute-mapper	\N	b8c68721-3d5d-4eb1-b159-c1b10444354f
4364f2ab-258d-4580-837a-40c762e8dae0	email	openid-connect	oidc-usermodel-property-mapper	\N	6636c59b-3a86-4336-91ab-5f1346fc2b37
f0c84e26-670b-4642-bbe8-34ab8bad0aa3	email verified	openid-connect	oidc-usermodel-property-mapper	\N	6636c59b-3a86-4336-91ab-5f1346fc2b37
20392db0-588f-4dd8-a998-4871f51d867e	address	openid-connect	oidc-address-mapper	\N	ffbae3cf-a1d4-4686-8efe-b1a917e77a0c
90d8e4af-c8cc-4235-8ec9-9d99e346ca4d	phone number	openid-connect	oidc-usermodel-attribute-mapper	\N	8ce8102c-9fbf-40fb-89f8-31787ca3fc6f
4e727b7d-fd94-4f6f-a17c-b4d45e0cae30	phone number verified	openid-connect	oidc-usermodel-attribute-mapper	\N	8ce8102c-9fbf-40fb-89f8-31787ca3fc6f
4a0c5f8e-4587-479a-96b6-13c1888781ac	realm roles	openid-connect	oidc-usermodel-realm-role-mapper	\N	0daba024-223b-4988-b5fc-7679fd97b9d1
84df9542-6f2e-4fc8-8d16-0f329bb38f9a	client roles	openid-connect	oidc-usermodel-client-role-mapper	\N	0daba024-223b-4988-b5fc-7679fd97b9d1
05c615cb-edf7-423a-9968-77e743d0669b	audience resolve	openid-connect	oidc-audience-resolve-mapper	\N	0daba024-223b-4988-b5fc-7679fd97b9d1
c77b150e-4e8f-482f-acfb-49182b305cf3	allowed web origins	openid-connect	oidc-allowed-origins-mapper	\N	a9bddfd0-3c77-4eda-b6cd-4a520b9f96fa
ff108b36-04cb-4472-bef2-b0bd2594d614	upn	openid-connect	oidc-usermodel-property-mapper	\N	51575d93-45e6-4b35-bf4a-37e4a2541c0e
f033b57d-5ddc-4474-9a92-228e9700ce0e	groups	openid-connect	oidc-usermodel-realm-role-mapper	\N	51575d93-45e6-4b35-bf4a-37e4a2541c0e
\.


--
-- Data for Name: protocol_mapper_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.protocol_mapper_config (protocol_mapper_id, value, name) FROM stdin;
8e8fcfe5-3f07-4a59-8d58-a02421a5bfda	true	userinfo.token.claim
8e8fcfe5-3f07-4a59-8d58-a02421a5bfda	locale	user.attribute
8e8fcfe5-3f07-4a59-8d58-a02421a5bfda	true	id.token.claim
8e8fcfe5-3f07-4a59-8d58-a02421a5bfda	true	access.token.claim
8e8fcfe5-3f07-4a59-8d58-a02421a5bfda	locale	claim.name
8e8fcfe5-3f07-4a59-8d58-a02421a5bfda	String	jsonType.label
285778bd-02d2-4dc0-80db-e4aed350bbf6	false	single
285778bd-02d2-4dc0-80db-e4aed350bbf6	Basic	attribute.nameformat
285778bd-02d2-4dc0-80db-e4aed350bbf6	Role	attribute.name
9d75d365-e1ac-4f52-b4ab-6751f6df038d	true	userinfo.token.claim
9d75d365-e1ac-4f52-b4ab-6751f6df038d	true	id.token.claim
9d75d365-e1ac-4f52-b4ab-6751f6df038d	true	access.token.claim
55286902-cf9e-4069-8796-0f65339ccf6f	true	userinfo.token.claim
55286902-cf9e-4069-8796-0f65339ccf6f	lastName	user.attribute
55286902-cf9e-4069-8796-0f65339ccf6f	true	id.token.claim
55286902-cf9e-4069-8796-0f65339ccf6f	true	access.token.claim
55286902-cf9e-4069-8796-0f65339ccf6f	family_name	claim.name
55286902-cf9e-4069-8796-0f65339ccf6f	String	jsonType.label
b432ad8d-e088-4764-9296-ecc8958036f1	true	userinfo.token.claim
b432ad8d-e088-4764-9296-ecc8958036f1	firstName	user.attribute
b432ad8d-e088-4764-9296-ecc8958036f1	true	id.token.claim
b432ad8d-e088-4764-9296-ecc8958036f1	true	access.token.claim
b432ad8d-e088-4764-9296-ecc8958036f1	given_name	claim.name
b432ad8d-e088-4764-9296-ecc8958036f1	String	jsonType.label
190bff59-0263-4dae-84bc-fb59825b3e79	true	userinfo.token.claim
190bff59-0263-4dae-84bc-fb59825b3e79	middleName	user.attribute
190bff59-0263-4dae-84bc-fb59825b3e79	true	id.token.claim
190bff59-0263-4dae-84bc-fb59825b3e79	true	access.token.claim
190bff59-0263-4dae-84bc-fb59825b3e79	middle_name	claim.name
190bff59-0263-4dae-84bc-fb59825b3e79	String	jsonType.label
38fdc4e1-f31e-44bf-a9bc-906579ef6979	true	userinfo.token.claim
38fdc4e1-f31e-44bf-a9bc-906579ef6979	nickname	user.attribute
38fdc4e1-f31e-44bf-a9bc-906579ef6979	true	id.token.claim
38fdc4e1-f31e-44bf-a9bc-906579ef6979	true	access.token.claim
38fdc4e1-f31e-44bf-a9bc-906579ef6979	nickname	claim.name
38fdc4e1-f31e-44bf-a9bc-906579ef6979	String	jsonType.label
3ba8413c-6fef-4a02-b8d8-2b0b98bfdb06	true	userinfo.token.claim
3ba8413c-6fef-4a02-b8d8-2b0b98bfdb06	username	user.attribute
3ba8413c-6fef-4a02-b8d8-2b0b98bfdb06	true	id.token.claim
3ba8413c-6fef-4a02-b8d8-2b0b98bfdb06	true	access.token.claim
3ba8413c-6fef-4a02-b8d8-2b0b98bfdb06	preferred_username	claim.name
3ba8413c-6fef-4a02-b8d8-2b0b98bfdb06	String	jsonType.label
476c8852-b534-45d7-bd4c-1da783888856	true	userinfo.token.claim
476c8852-b534-45d7-bd4c-1da783888856	profile	user.attribute
476c8852-b534-45d7-bd4c-1da783888856	true	id.token.claim
476c8852-b534-45d7-bd4c-1da783888856	true	access.token.claim
476c8852-b534-45d7-bd4c-1da783888856	profile	claim.name
476c8852-b534-45d7-bd4c-1da783888856	String	jsonType.label
65d20680-99ba-485a-9365-f7155d41bb6a	true	userinfo.token.claim
65d20680-99ba-485a-9365-f7155d41bb6a	picture	user.attribute
65d20680-99ba-485a-9365-f7155d41bb6a	true	id.token.claim
65d20680-99ba-485a-9365-f7155d41bb6a	true	access.token.claim
65d20680-99ba-485a-9365-f7155d41bb6a	picture	claim.name
65d20680-99ba-485a-9365-f7155d41bb6a	String	jsonType.label
6316e814-247f-4dc1-8506-ce11254b6f11	true	userinfo.token.claim
6316e814-247f-4dc1-8506-ce11254b6f11	website	user.attribute
6316e814-247f-4dc1-8506-ce11254b6f11	true	id.token.claim
6316e814-247f-4dc1-8506-ce11254b6f11	true	access.token.claim
6316e814-247f-4dc1-8506-ce11254b6f11	website	claim.name
6316e814-247f-4dc1-8506-ce11254b6f11	String	jsonType.label
68e954d0-55f7-44a5-aaca-22a7b3bdec65	true	userinfo.token.claim
68e954d0-55f7-44a5-aaca-22a7b3bdec65	gender	user.attribute
68e954d0-55f7-44a5-aaca-22a7b3bdec65	true	id.token.claim
68e954d0-55f7-44a5-aaca-22a7b3bdec65	true	access.token.claim
68e954d0-55f7-44a5-aaca-22a7b3bdec65	gender	claim.name
68e954d0-55f7-44a5-aaca-22a7b3bdec65	String	jsonType.label
598d77be-f31f-4783-87f0-418e34fe7bfc	true	userinfo.token.claim
598d77be-f31f-4783-87f0-418e34fe7bfc	birthdate	user.attribute
598d77be-f31f-4783-87f0-418e34fe7bfc	true	id.token.claim
598d77be-f31f-4783-87f0-418e34fe7bfc	true	access.token.claim
598d77be-f31f-4783-87f0-418e34fe7bfc	birthdate	claim.name
598d77be-f31f-4783-87f0-418e34fe7bfc	String	jsonType.label
1ecb75b1-90d6-4eea-8bba-33e29e4637d2	true	userinfo.token.claim
1ecb75b1-90d6-4eea-8bba-33e29e4637d2	zoneinfo	user.attribute
1ecb75b1-90d6-4eea-8bba-33e29e4637d2	true	id.token.claim
1ecb75b1-90d6-4eea-8bba-33e29e4637d2	true	access.token.claim
1ecb75b1-90d6-4eea-8bba-33e29e4637d2	zoneinfo	claim.name
1ecb75b1-90d6-4eea-8bba-33e29e4637d2	String	jsonType.label
be28faac-473a-4403-bad8-955a126d999f	true	userinfo.token.claim
be28faac-473a-4403-bad8-955a126d999f	locale	user.attribute
be28faac-473a-4403-bad8-955a126d999f	true	id.token.claim
be28faac-473a-4403-bad8-955a126d999f	true	access.token.claim
be28faac-473a-4403-bad8-955a126d999f	locale	claim.name
be28faac-473a-4403-bad8-955a126d999f	String	jsonType.label
46beb4f4-8146-4886-81c2-e92b2b29a419	true	userinfo.token.claim
46beb4f4-8146-4886-81c2-e92b2b29a419	updatedAt	user.attribute
46beb4f4-8146-4886-81c2-e92b2b29a419	true	id.token.claim
46beb4f4-8146-4886-81c2-e92b2b29a419	true	access.token.claim
46beb4f4-8146-4886-81c2-e92b2b29a419	updated_at	claim.name
46beb4f4-8146-4886-81c2-e92b2b29a419	String	jsonType.label
4364f2ab-258d-4580-837a-40c762e8dae0	true	userinfo.token.claim
4364f2ab-258d-4580-837a-40c762e8dae0	email	user.attribute
4364f2ab-258d-4580-837a-40c762e8dae0	true	id.token.claim
4364f2ab-258d-4580-837a-40c762e8dae0	true	access.token.claim
4364f2ab-258d-4580-837a-40c762e8dae0	email	claim.name
4364f2ab-258d-4580-837a-40c762e8dae0	String	jsonType.label
f0c84e26-670b-4642-bbe8-34ab8bad0aa3	true	userinfo.token.claim
f0c84e26-670b-4642-bbe8-34ab8bad0aa3	emailVerified	user.attribute
f0c84e26-670b-4642-bbe8-34ab8bad0aa3	true	id.token.claim
f0c84e26-670b-4642-bbe8-34ab8bad0aa3	true	access.token.claim
f0c84e26-670b-4642-bbe8-34ab8bad0aa3	email_verified	claim.name
f0c84e26-670b-4642-bbe8-34ab8bad0aa3	boolean	jsonType.label
20392db0-588f-4dd8-a998-4871f51d867e	formatted	user.attribute.formatted
20392db0-588f-4dd8-a998-4871f51d867e	country	user.attribute.country
20392db0-588f-4dd8-a998-4871f51d867e	postal_code	user.attribute.postal_code
20392db0-588f-4dd8-a998-4871f51d867e	true	userinfo.token.claim
20392db0-588f-4dd8-a998-4871f51d867e	street	user.attribute.street
20392db0-588f-4dd8-a998-4871f51d867e	true	id.token.claim
20392db0-588f-4dd8-a998-4871f51d867e	region	user.attribute.region
20392db0-588f-4dd8-a998-4871f51d867e	true	access.token.claim
20392db0-588f-4dd8-a998-4871f51d867e	locality	user.attribute.locality
90d8e4af-c8cc-4235-8ec9-9d99e346ca4d	true	userinfo.token.claim
90d8e4af-c8cc-4235-8ec9-9d99e346ca4d	phoneNumber	user.attribute
90d8e4af-c8cc-4235-8ec9-9d99e346ca4d	true	id.token.claim
90d8e4af-c8cc-4235-8ec9-9d99e346ca4d	true	access.token.claim
90d8e4af-c8cc-4235-8ec9-9d99e346ca4d	phone_number	claim.name
90d8e4af-c8cc-4235-8ec9-9d99e346ca4d	String	jsonType.label
4e727b7d-fd94-4f6f-a17c-b4d45e0cae30	true	userinfo.token.claim
4e727b7d-fd94-4f6f-a17c-b4d45e0cae30	phoneNumberVerified	user.attribute
4e727b7d-fd94-4f6f-a17c-b4d45e0cae30	true	id.token.claim
4e727b7d-fd94-4f6f-a17c-b4d45e0cae30	true	access.token.claim
4e727b7d-fd94-4f6f-a17c-b4d45e0cae30	phone_number_verified	claim.name
4e727b7d-fd94-4f6f-a17c-b4d45e0cae30	boolean	jsonType.label
4a0c5f8e-4587-479a-96b6-13c1888781ac	true	multivalued
4a0c5f8e-4587-479a-96b6-13c1888781ac	foo	user.attribute
4a0c5f8e-4587-479a-96b6-13c1888781ac	true	access.token.claim
4a0c5f8e-4587-479a-96b6-13c1888781ac	realm_access.roles	claim.name
4a0c5f8e-4587-479a-96b6-13c1888781ac	String	jsonType.label
84df9542-6f2e-4fc8-8d16-0f329bb38f9a	true	multivalued
84df9542-6f2e-4fc8-8d16-0f329bb38f9a	foo	user.attribute
84df9542-6f2e-4fc8-8d16-0f329bb38f9a	true	access.token.claim
84df9542-6f2e-4fc8-8d16-0f329bb38f9a	resource_access.${client_id}.roles	claim.name
84df9542-6f2e-4fc8-8d16-0f329bb38f9a	String	jsonType.label
ff108b36-04cb-4472-bef2-b0bd2594d614	true	userinfo.token.claim
ff108b36-04cb-4472-bef2-b0bd2594d614	username	user.attribute
ff108b36-04cb-4472-bef2-b0bd2594d614	true	id.token.claim
ff108b36-04cb-4472-bef2-b0bd2594d614	true	access.token.claim
ff108b36-04cb-4472-bef2-b0bd2594d614	upn	claim.name
ff108b36-04cb-4472-bef2-b0bd2594d614	String	jsonType.label
f033b57d-5ddc-4474-9a92-228e9700ce0e	true	multivalued
f033b57d-5ddc-4474-9a92-228e9700ce0e	foo	user.attribute
f033b57d-5ddc-4474-9a92-228e9700ce0e	true	id.token.claim
f033b57d-5ddc-4474-9a92-228e9700ce0e	true	access.token.claim
f033b57d-5ddc-4474-9a92-228e9700ce0e	groups	claim.name
f033b57d-5ddc-4474-9a92-228e9700ce0e	String	jsonType.label
\.


--
-- Data for Name: realm; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm (id, access_code_lifespan, user_action_lifespan, access_token_lifespan, account_theme, admin_theme, email_theme, enabled, events_enabled, events_expiration, login_theme, name, not_before, password_policy, registration_allowed, remember_me, reset_password_allowed, social, ssl_required, sso_idle_timeout, sso_max_lifespan, update_profile_on_soc_login, verify_email, master_admin_client, login_lifespan, internationalization_enabled, default_locale, reg_email_as_username, admin_events_enabled, admin_events_details_enabled, edit_username_allowed, otp_policy_counter, otp_policy_window, otp_policy_period, otp_policy_digits, otp_policy_alg, otp_policy_type, browser_flow, registration_flow, direct_grant_flow, reset_credentials_flow, client_auth_flow, offline_session_idle_timeout, revoke_refresh_token, access_token_life_implicit, login_with_email_allowed, duplicate_emails_allowed, docker_auth_flow, refresh_token_max_reuse, allow_user_managed_access, sso_max_lifespan_remember_me, sso_idle_timeout_remember_me) FROM stdin;
master	60	300	60	\N	\N	\N	t	f	0	\N	master	0	\N	f	f	f	f	EXTERNAL	1800	36000	f	f	31f12df6-585a-4c33-85be-57a0e11589a5	1800	f	\N	f	f	f	f	0	1	30	6	HmacSHA1	totp	114581d0-6ef9-4a6a-b6ce-6ec08045422f	7750c1f2-7d91-410a-aedd-7c5b43c5323b	7bc696c9-3787-4c74-8fbd-6a0c3ce02b91	dde9f98f-3689-42f9-9fc0-d27b814237ce	a490b6cd-f301-4792-8de0-10bdfc82f48c	2592000	f	900	t	f	55bfe350-e249-48eb-ad87-114b1b1481c0	0	f	0	0
\.


--
-- Data for Name: realm_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_attribute (name, value, realm_id) FROM stdin;
_browser_header.contentSecurityPolicyReportOnly		master
_browser_header.xContentTypeOptions	nosniff	master
_browser_header.xRobotsTag	none	master
_browser_header.xFrameOptions	SAMEORIGIN	master
_browser_header.contentSecurityPolicy	frame-src 'self'; frame-ancestors 'self'; object-src 'none';	master
_browser_header.xXSSProtection	1; mode=block	master
_browser_header.strictTransportSecurity	max-age=31536000; includeSubDomains	master
bruteForceProtected	false	master
permanentLockout	false	master
maxFailureWaitSeconds	900	master
minimumQuickLoginWaitSeconds	60	master
waitIncrementSeconds	60	master
quickLoginCheckMilliSeconds	1000	master
maxDeltaTimeSeconds	43200	master
failureFactor	30	master
displayName	Keycloak	master
displayNameHtml	<div class="kc-logo-text"><span>Keycloak</span></div>	master
offlineSessionMaxLifespanEnabled	false	master
offlineSessionMaxLifespan	5184000	master
\.


--
-- Data for Name: realm_default_groups; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_default_groups (realm_id, group_id) FROM stdin;
\.


--
-- Data for Name: realm_default_roles; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_default_roles (realm_id, role_id) FROM stdin;
master	af0cc155-6222-4a13-b495-a428a79397f2
master	0b735fa1-f21d-4c5d-b51b-9710cc89e844
\.


--
-- Data for Name: realm_enabled_event_types; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_enabled_event_types (realm_id, value) FROM stdin;
\.


--
-- Data for Name: realm_events_listeners; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_events_listeners (realm_id, value) FROM stdin;
master	jboss-logging
\.


--
-- Data for Name: realm_required_credential; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_required_credential (type, form_label, input, secret, realm_id) FROM stdin;
password	password	t	t	master
\.


--
-- Data for Name: realm_smtp_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_smtp_config (realm_id, value, name) FROM stdin;
\.


--
-- Data for Name: realm_supported_locales; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_supported_locales (realm_id, value) FROM stdin;
\.


--
-- Data for Name: redirect_uris; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.redirect_uris (client_id, value) FROM stdin;
a36896c5-9de3-420b-aed0-cd2d3c7f746b	/auth/realms/master/account/*
8006cce4-48e0-4caa-9192-cdbea13985ab	/auth/admin/master/console/*
b361b54a-44b9-482c-b323-c25841bad11c	http://app-flaminem.localtest.me:6092/*
\.


--
-- Data for Name: required_action_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.required_action_config (required_action_id, value, name) FROM stdin;
\.


--
-- Data for Name: required_action_provider; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.required_action_provider (id, alias, name, realm_id, enabled, default_action, provider_id, priority) FROM stdin;
a0502017-6011-417c-ae9d-74a52de8e633	VERIFY_EMAIL	Verify Email	master	t	f	VERIFY_EMAIL	50
5572f559-5487-4a58-bbc0-d5d9c999dce0	UPDATE_PROFILE	Update Profile	master	t	f	UPDATE_PROFILE	40
6d0e628a-0757-49ef-a705-fef0225bfef1	CONFIGURE_TOTP	Configure OTP	master	t	f	CONFIGURE_TOTP	10
11cf0c73-f8da-4ab4-9435-37c6f5759447	UPDATE_PASSWORD	Update Password	master	t	f	UPDATE_PASSWORD	30
2a1eb305-27b2-49ec-b5d6-7bdc17468882	terms_and_conditions	Terms and Conditions	master	f	f	terms_and_conditions	20
\.


--
-- Data for Name: resource_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_attribute (id, name, value, resource_id) FROM stdin;
\.


--
-- Data for Name: resource_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_policy (resource_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_scope (resource_id, scope_id) FROM stdin;
\.


--
-- Data for Name: resource_server; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server (id, allow_rs_remote_mgmt, policy_enforce_mode, decision_strategy) FROM stdin;
\.


--
-- Data for Name: resource_server_perm_ticket; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_perm_ticket (id, owner, requester, created_timestamp, granted_timestamp, resource_id, scope_id, resource_server_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_server_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_policy (id, name, description, type, decision_strategy, logic, resource_server_id, owner) FROM stdin;
\.


--
-- Data for Name: resource_server_resource; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_resource (id, name, type, icon_uri, owner, resource_server_id, owner_managed_access, display_name) FROM stdin;
\.


--
-- Data for Name: resource_server_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_scope (id, name, icon_uri, resource_server_id, display_name) FROM stdin;
\.


--
-- Data for Name: resource_uris; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_uris (resource_id, value) FROM stdin;
\.


--
-- Data for Name: role_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.role_attribute (id, role_id, name, value) FROM stdin;
\.


--
-- Data for Name: scope_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.scope_mapping (client_id, role_id) FROM stdin;
\.


--
-- Data for Name: scope_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.scope_policy (scope_id, policy_id) FROM stdin;
\.


--
-- Data for Name: user_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_attribute (name, value, user_id, id) FROM stdin;
\.


--
-- Data for Name: user_consent; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_consent (id, client_id, user_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: user_consent_client_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_consent_client_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: user_entity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_entity (id, email, email_constraint, email_verified, enabled, federation_link, first_name, last_name, realm_id, username, created_timestamp, service_account_client_link, not_before) FROM stdin;
b0f34c1d-10c5-41f1-a22d-a56833163617	\N	fad115ce-657c-4961-8faf-a0aeb88c2906	f	t	\N	\N	\N	master	admin	1567771138518	\N	0
\.


--
-- Data for Name: user_federation_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_config (user_federation_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_mapper (id, name, federation_provider_id, federation_mapper_type, realm_id) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_mapper_config (user_federation_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_provider; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_provider (id, changed_sync_period, display_name, full_sync_period, last_sync, priority, provider_name, realm_id) FROM stdin;
\.


--
-- Data for Name: user_group_membership; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_group_membership (group_id, user_id) FROM stdin;
\.


--
-- Data for Name: user_required_action; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_required_action (user_id, required_action) FROM stdin;
\.


--
-- Data for Name: user_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_role_mapping (role_id, user_id) FROM stdin;
af0cc155-6222-4a13-b495-a428a79397f2	b0f34c1d-10c5-41f1-a22d-a56833163617
0b735fa1-f21d-4c5d-b51b-9710cc89e844	b0f34c1d-10c5-41f1-a22d-a56833163617
762e168b-8230-47c9-a927-b7d367aa86cc	b0f34c1d-10c5-41f1-a22d-a56833163617
56a85ca2-8273-4ec2-b49d-d991066a42af	b0f34c1d-10c5-41f1-a22d-a56833163617
b94dfea8-e155-43df-baf0-442311859ac7	b0f34c1d-10c5-41f1-a22d-a56833163617
\.


--
-- Data for Name: user_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_session (id, auth_method, ip_address, last_session_refresh, login_username, realm_id, remember_me, started, user_id, user_session_state, broker_session_id, broker_user_id) FROM stdin;
\.


--
-- Data for Name: user_session_note; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_session_note (user_session, name, value) FROM stdin;
\.


--
-- Data for Name: username_login_failure; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.username_login_failure (realm_id, username, failed_login_not_before, last_failure, last_ip_failure, num_failures) FROM stdin;
\.


--
-- Data for Name: web_origins; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.web_origins (client_id, value) FROM stdin;
b361b54a-44b9-482c-b323-c25841bad11c	http://app-flaminem.localtest.me:6092
\.


--
-- Name: username_login_failure CONSTRAINT_17-2; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.username_login_failure
    ADD CONSTRAINT "CONSTRAINT_17-2" PRIMARY KEY (realm_id, username);


--
-- Name: keycloak_role UK_J3RWUVD56ONTGSUHOGM184WW2-2; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT "UK_J3RWUVD56ONTGSUHOGM184WW2-2" UNIQUE (name, client_realm_constraint);


--
-- Name: client_auth_flow_bindings c_cli_flow_bind; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_auth_flow_bindings
    ADD CONSTRAINT c_cli_flow_bind PRIMARY KEY (client_id, binding_name);


--
-- Name: client_scope_client c_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT c_cli_scope_bind PRIMARY KEY (client_id, scope_id);


--
-- Name: client_initial_access cnstr_client_init_acc_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT cnstr_client_init_acc_pk PRIMARY KEY (id);


--
-- Name: realm_default_groups con_group_id_def_groups; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT con_group_id_def_groups UNIQUE (group_id);


--
-- Name: broker_link constr_broker_link_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.broker_link
    ADD CONSTRAINT constr_broker_link_pk PRIMARY KEY (identity_provider, user_id);


--
-- Name: client_user_session_note constr_cl_usr_ses_note; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_user_session_note
    ADD CONSTRAINT constr_cl_usr_ses_note PRIMARY KEY (client_session, name);


--
-- Name: client_default_roles constr_client_default_roles; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT constr_client_default_roles PRIMARY KEY (client_id, role_id);


--
-- Name: component_config constr_component_config_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT constr_component_config_pk PRIMARY KEY (id);


--
-- Name: component constr_component_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT constr_component_pk PRIMARY KEY (id);


--
-- Name: fed_user_required_action constr_fed_required_action; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_required_action
    ADD CONSTRAINT constr_fed_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: fed_user_attribute constr_fed_user_attr_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_attribute
    ADD CONSTRAINT constr_fed_user_attr_pk PRIMARY KEY (id);


--
-- Name: fed_user_consent constr_fed_user_consent_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_consent
    ADD CONSTRAINT constr_fed_user_consent_pk PRIMARY KEY (id);


--
-- Name: fed_user_credential constr_fed_user_cred_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_credential
    ADD CONSTRAINT constr_fed_user_cred_pk PRIMARY KEY (id);


--
-- Name: fed_user_group_membership constr_fed_user_group; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_group_membership
    ADD CONSTRAINT constr_fed_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: fed_user_role_mapping constr_fed_user_role; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_role_mapping
    ADD CONSTRAINT constr_fed_user_role PRIMARY KEY (role_id, user_id);


--
-- Name: federated_user constr_federated_user; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.federated_user
    ADD CONSTRAINT constr_federated_user PRIMARY KEY (id);


--
-- Name: realm_default_groups constr_realm_default_groups; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT constr_realm_default_groups PRIMARY KEY (realm_id, group_id);


--
-- Name: realm_enabled_event_types constr_realm_enabl_event_types; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT constr_realm_enabl_event_types PRIMARY KEY (realm_id, value);


--
-- Name: realm_events_listeners constr_realm_events_listeners; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT constr_realm_events_listeners PRIMARY KEY (realm_id, value);


--
-- Name: realm_supported_locales constr_realm_supported_locales; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT constr_realm_supported_locales PRIMARY KEY (realm_id, value);


--
-- Name: identity_provider constraint_2b; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT constraint_2b PRIMARY KEY (internal_id);


--
-- Name: client_attributes constraint_3c; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT constraint_3c PRIMARY KEY (client_id, name);


--
-- Name: event_entity constraint_4; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.event_entity
    ADD CONSTRAINT constraint_4 PRIMARY KEY (id);


--
-- Name: federated_identity constraint_40; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT constraint_40 PRIMARY KEY (identity_provider, user_id);


--
-- Name: realm constraint_4a; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT constraint_4a PRIMARY KEY (id);


--
-- Name: client_session_role constraint_5; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_role
    ADD CONSTRAINT constraint_5 PRIMARY KEY (client_session, role_id);


--
-- Name: user_session constraint_57; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_session
    ADD CONSTRAINT constraint_57 PRIMARY KEY (id);


--
-- Name: user_federation_provider constraint_5c; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT constraint_5c PRIMARY KEY (id);


--
-- Name: client_session_note constraint_5e; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_note
    ADD CONSTRAINT constraint_5e PRIMARY KEY (client_session, name);


--
-- Name: client constraint_7; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT constraint_7 PRIMARY KEY (id);


--
-- Name: client_session constraint_8; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session
    ADD CONSTRAINT constraint_8 PRIMARY KEY (id);


--
-- Name: scope_mapping constraint_81; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT constraint_81 PRIMARY KEY (client_id, role_id);


--
-- Name: client_node_registrations constraint_84; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT constraint_84 PRIMARY KEY (client_id, name);


--
-- Name: realm_attribute constraint_9; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT constraint_9 PRIMARY KEY (name, realm_id);


--
-- Name: realm_required_credential constraint_92; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT constraint_92 PRIMARY KEY (realm_id, type);


--
-- Name: keycloak_role constraint_a; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT constraint_a PRIMARY KEY (id);


--
-- Name: admin_event_entity constraint_admin_event_entity; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.admin_event_entity
    ADD CONSTRAINT constraint_admin_event_entity PRIMARY KEY (id);


--
-- Name: authenticator_config_entry constraint_auth_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authenticator_config_entry
    ADD CONSTRAINT constraint_auth_cfg_pk PRIMARY KEY (authenticator_id, name);


--
-- Name: authentication_execution constraint_auth_exec_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT constraint_auth_exec_pk PRIMARY KEY (id);


--
-- Name: authentication_flow constraint_auth_flow_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT constraint_auth_flow_pk PRIMARY KEY (id);


--
-- Name: authenticator_config constraint_auth_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT constraint_auth_pk PRIMARY KEY (id);


--
-- Name: client_session_auth_status constraint_auth_status_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_auth_status
    ADD CONSTRAINT constraint_auth_status_pk PRIMARY KEY (client_session, authenticator);


--
-- Name: user_role_mapping constraint_c; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT constraint_c PRIMARY KEY (role_id, user_id);


--
-- Name: composite_role constraint_composite_role; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT constraint_composite_role PRIMARY KEY (composite, child_role);


--
-- Name: credential_attribute constraint_credential_attr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential_attribute
    ADD CONSTRAINT constraint_credential_attr PRIMARY KEY (id);


--
-- Name: client_session_prot_mapper constraint_cs_pmp_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_prot_mapper
    ADD CONSTRAINT constraint_cs_pmp_pk PRIMARY KEY (client_session, protocol_mapper_id);


--
-- Name: identity_provider_config constraint_d; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT constraint_d PRIMARY KEY (identity_provider_id, name);


--
-- Name: policy_config constraint_dpc; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT constraint_dpc PRIMARY KEY (policy_id, name);


--
-- Name: realm_smtp_config constraint_e; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT constraint_e PRIMARY KEY (realm_id, name);


--
-- Name: credential constraint_f; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT constraint_f PRIMARY KEY (id);


--
-- Name: user_federation_config constraint_f9; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT constraint_f9 PRIMARY KEY (user_federation_provider_id, name);


--
-- Name: resource_server_perm_ticket constraint_fapmt; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT constraint_fapmt PRIMARY KEY (id);


--
-- Name: resource_server_resource constraint_farsr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT constraint_farsr PRIMARY KEY (id);


--
-- Name: resource_server_policy constraint_farsrp; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT constraint_farsrp PRIMARY KEY (id);


--
-- Name: associated_policy constraint_farsrpap; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT constraint_farsrpap PRIMARY KEY (policy_id, associated_policy_id);


--
-- Name: resource_policy constraint_farsrpp; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT constraint_farsrpp PRIMARY KEY (resource_id, policy_id);


--
-- Name: resource_server_scope constraint_farsrs; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT constraint_farsrs PRIMARY KEY (id);


--
-- Name: resource_scope constraint_farsrsp; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT constraint_farsrsp PRIMARY KEY (resource_id, scope_id);


--
-- Name: scope_policy constraint_farsrsps; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT constraint_farsrsps PRIMARY KEY (scope_id, policy_id);


--
-- Name: user_entity constraint_fb; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT constraint_fb PRIMARY KEY (id);


--
-- Name: fed_credential_attribute constraint_fed_credential_attr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_credential_attribute
    ADD CONSTRAINT constraint_fed_credential_attr PRIMARY KEY (id);


--
-- Name: user_federation_mapper_config constraint_fedmapper_cfg_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT constraint_fedmapper_cfg_pm PRIMARY KEY (user_federation_mapper_id, name);


--
-- Name: user_federation_mapper constraint_fedmapperpm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT constraint_fedmapperpm PRIMARY KEY (id);


--
-- Name: fed_user_consent_cl_scope constraint_fgrntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_consent_cl_scope
    ADD CONSTRAINT constraint_fgrntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent_client_scope constraint_grntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT constraint_grntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent constraint_grntcsnt_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT constraint_grntcsnt_pm PRIMARY KEY (id);


--
-- Name: keycloak_group constraint_group; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT constraint_group PRIMARY KEY (id);


--
-- Name: group_attribute constraint_group_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT constraint_group_attribute_pk PRIMARY KEY (id);


--
-- Name: group_role_mapping constraint_group_role; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT constraint_group_role PRIMARY KEY (role_id, group_id);


--
-- Name: identity_provider_mapper constraint_idpm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT constraint_idpm PRIMARY KEY (id);


--
-- Name: idp_mapper_config constraint_idpmconfig; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT constraint_idpmconfig PRIMARY KEY (idp_mapper_id, name);


--
-- Name: migration_model constraint_migmod; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.migration_model
    ADD CONSTRAINT constraint_migmod PRIMARY KEY (id);


--
-- Name: offline_client_session constraint_offl_cl_ses_pk3; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.offline_client_session
    ADD CONSTRAINT constraint_offl_cl_ses_pk3 PRIMARY KEY (user_session_id, client_id, client_storage_provider, external_client_id, offline_flag);


--
-- Name: offline_user_session constraint_offl_us_ses_pk2; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.offline_user_session
    ADD CONSTRAINT constraint_offl_us_ses_pk2 PRIMARY KEY (user_session_id, offline_flag);


--
-- Name: protocol_mapper constraint_pcm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT constraint_pcm PRIMARY KEY (id);


--
-- Name: protocol_mapper_config constraint_pmconfig; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT constraint_pmconfig PRIMARY KEY (protocol_mapper_id, name);


--
-- Name: realm_default_roles constraint_realm_default_roles; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT constraint_realm_default_roles PRIMARY KEY (realm_id, role_id);


--
-- Name: redirect_uris constraint_redirect_uris; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT constraint_redirect_uris PRIMARY KEY (client_id, value);


--
-- Name: required_action_config constraint_req_act_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.required_action_config
    ADD CONSTRAINT constraint_req_act_cfg_pk PRIMARY KEY (required_action_id, name);


--
-- Name: required_action_provider constraint_req_act_prv_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT constraint_req_act_prv_pk PRIMARY KEY (id);


--
-- Name: user_required_action constraint_required_action; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT constraint_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: resource_uris constraint_resour_uris_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT constraint_resour_uris_pk PRIMARY KEY (resource_id, value);


--
-- Name: role_attribute constraint_role_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT constraint_role_attribute_pk PRIMARY KEY (id);


--
-- Name: user_attribute constraint_user_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT constraint_user_attribute_pk PRIMARY KEY (id);


--
-- Name: user_group_membership constraint_user_group; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT constraint_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: user_session_note constraint_usn_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_session_note
    ADD CONSTRAINT constraint_usn_pk PRIMARY KEY (user_session, name);


--
-- Name: web_origins constraint_web_origins; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT constraint_web_origins PRIMARY KEY (client_id, value);


--
-- Name: client_scope_attributes pk_cl_tmpl_attr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT pk_cl_tmpl_attr PRIMARY KEY (scope_id, name);


--
-- Name: client_scope pk_cli_template; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT pk_cli_template PRIMARY KEY (id);


--
-- Name: databasechangeloglock pk_databasechangeloglock; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.databasechangeloglock
    ADD CONSTRAINT pk_databasechangeloglock PRIMARY KEY (id);


--
-- Name: resource_server pk_resource_server; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server
    ADD CONSTRAINT pk_resource_server PRIMARY KEY (id);


--
-- Name: client_scope_role_mapping pk_template_scope; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT pk_template_scope PRIMARY KEY (scope_id, role_id);


--
-- Name: default_client_scope r_def_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT r_def_cli_scope_bind PRIMARY KEY (realm_id, scope_id);


--
-- Name: resource_attribute res_attr_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT res_attr_pk PRIMARY KEY (id);


--
-- Name: keycloak_group sibling_names; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT sibling_names UNIQUE (realm_id, parent_group, name);


--
-- Name: identity_provider uk_2daelwnibji49avxsrtuf6xj33; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT uk_2daelwnibji49avxsrtuf6xj33 UNIQUE (provider_alias, realm_id);


--
-- Name: client_default_roles uk_8aelwnibji49avxsrtuf6xjow; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT uk_8aelwnibji49avxsrtuf6xjow UNIQUE (role_id);


--
-- Name: client uk_b71cjlbenv945rb6gcon438at; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT uk_b71cjlbenv945rb6gcon438at UNIQUE (realm_id, client_id);


--
-- Name: client_scope uk_cli_scope; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT uk_cli_scope UNIQUE (realm_id, name);


--
-- Name: user_entity uk_dykn684sl8up1crfei6eckhd7; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_dykn684sl8up1crfei6eckhd7 UNIQUE (realm_id, email_constraint);


--
-- Name: resource_server_resource uk_frsr6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5ha6 UNIQUE (name, owner, resource_server_id);


--
-- Name: resource_server_perm_ticket uk_frsr6t700s9v50bu18ws5pmt; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5pmt UNIQUE (owner, requester, resource_server_id, resource_id, scope_id);


--
-- Name: resource_server_policy uk_frsrpt700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT uk_frsrpt700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: resource_server_scope uk_frsrst700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT uk_frsrst700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: realm_default_roles uk_h4wpd7w4hsoolni3h0sw7btje; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT uk_h4wpd7w4hsoolni3h0sw7btje UNIQUE (role_id);


--
-- Name: user_consent uk_jkuwuvd56ontgsuhogm8uewrt; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT uk_jkuwuvd56ontgsuhogm8uewrt UNIQUE (client_id, client_storage_provider, external_client_id, user_id);


--
-- Name: realm uk_orvsdmla56612eaefiq6wl5oi; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT uk_orvsdmla56612eaefiq6wl5oi UNIQUE (name);


--
-- Name: user_entity uk_ru8tt6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_ru8tt6t700s9v50bu18ws5ha6 UNIQUE (realm_id, username);


--
-- Name: idx_assoc_pol_assoc_pol_id; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_assoc_pol_assoc_pol_id ON public.associated_policy USING btree (associated_policy_id);


--
-- Name: idx_auth_config_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_config_realm ON public.authenticator_config USING btree (realm_id);


--
-- Name: idx_auth_exec_flow; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_exec_flow ON public.authentication_execution USING btree (flow_id);


--
-- Name: idx_auth_exec_realm_flow; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_exec_realm_flow ON public.authentication_execution USING btree (realm_id, flow_id);


--
-- Name: idx_auth_flow_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_flow_realm ON public.authentication_flow USING btree (realm_id);


--
-- Name: idx_cl_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_cl_clscope ON public.client_scope_client USING btree (scope_id);


--
-- Name: idx_client_def_roles_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_client_def_roles_client ON public.client_default_roles USING btree (client_id);


--
-- Name: idx_client_init_acc_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_client_init_acc_realm ON public.client_initial_access USING btree (realm_id);


--
-- Name: idx_client_session_session; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_client_session_session ON public.client_session USING btree (session_id);


--
-- Name: idx_clscope_attrs; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_attrs ON public.client_scope_attributes USING btree (scope_id);


--
-- Name: idx_clscope_cl; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_cl ON public.client_scope_client USING btree (client_id);


--
-- Name: idx_clscope_protmap; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_protmap ON public.protocol_mapper USING btree (client_scope_id);


--
-- Name: idx_clscope_role; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_role ON public.client_scope_role_mapping USING btree (scope_id);


--
-- Name: idx_compo_config_compo; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_compo_config_compo ON public.component_config USING btree (component_id);


--
-- Name: idx_component_provider_type; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_component_provider_type ON public.component USING btree (provider_type);


--
-- Name: idx_component_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_component_realm ON public.component USING btree (realm_id);


--
-- Name: idx_composite; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_composite ON public.composite_role USING btree (composite);


--
-- Name: idx_composite_child; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_composite_child ON public.composite_role USING btree (child_role);


--
-- Name: idx_credential_attr_cred; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_credential_attr_cred ON public.credential_attribute USING btree (credential_id);


--
-- Name: idx_defcls_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_defcls_realm ON public.default_client_scope USING btree (realm_id);


--
-- Name: idx_defcls_scope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_defcls_scope ON public.default_client_scope USING btree (scope_id);


--
-- Name: idx_fed_cred_attr_cred; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fed_cred_attr_cred ON public.fed_credential_attribute USING btree (credential_id);


--
-- Name: idx_fedidentity_feduser; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fedidentity_feduser ON public.federated_identity USING btree (federated_user_id);


--
-- Name: idx_fedidentity_user; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fedidentity_user ON public.federated_identity USING btree (user_id);


--
-- Name: idx_fu_attribute; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_attribute ON public.fed_user_attribute USING btree (user_id, realm_id, name);


--
-- Name: idx_fu_cnsnt_ext; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_cnsnt_ext ON public.fed_user_consent USING btree (user_id, client_storage_provider, external_client_id);


--
-- Name: idx_fu_consent; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_consent ON public.fed_user_consent USING btree (user_id, client_id);


--
-- Name: idx_fu_consent_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_consent_ru ON public.fed_user_consent USING btree (realm_id, user_id);


--
-- Name: idx_fu_credential; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_credential ON public.fed_user_credential USING btree (user_id, type);


--
-- Name: idx_fu_credential_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_credential_ru ON public.fed_user_credential USING btree (realm_id, user_id);


--
-- Name: idx_fu_group_membership; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_group_membership ON public.fed_user_group_membership USING btree (user_id, group_id);


--
-- Name: idx_fu_group_membership_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_group_membership_ru ON public.fed_user_group_membership USING btree (realm_id, user_id);


--
-- Name: idx_fu_required_action; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_required_action ON public.fed_user_required_action USING btree (user_id, required_action);


--
-- Name: idx_fu_required_action_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_required_action_ru ON public.fed_user_required_action USING btree (realm_id, user_id);


--
-- Name: idx_fu_role_mapping; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_role_mapping ON public.fed_user_role_mapping USING btree (user_id, role_id);


--
-- Name: idx_fu_role_mapping_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_role_mapping_ru ON public.fed_user_role_mapping USING btree (realm_id, user_id);


--
-- Name: idx_group_attr_group; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_group_attr_group ON public.group_attribute USING btree (group_id);


--
-- Name: idx_group_role_mapp_group; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_group_role_mapp_group ON public.group_role_mapping USING btree (group_id);


--
-- Name: idx_id_prov_mapp_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_id_prov_mapp_realm ON public.identity_provider_mapper USING btree (realm_id);


--
-- Name: idx_ident_prov_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_ident_prov_realm ON public.identity_provider USING btree (realm_id);


--
-- Name: idx_keycloak_role_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_keycloak_role_client ON public.keycloak_role USING btree (client);


--
-- Name: idx_keycloak_role_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_keycloak_role_realm ON public.keycloak_role USING btree (realm);


--
-- Name: idx_offline_uss_createdon; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_offline_uss_createdon ON public.offline_user_session USING btree (created_on);


--
-- Name: idx_protocol_mapper_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_protocol_mapper_client ON public.protocol_mapper USING btree (client_id);


--
-- Name: idx_realm_attr_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_attr_realm ON public.realm_attribute USING btree (realm_id);


--
-- Name: idx_realm_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_clscope ON public.client_scope USING btree (realm_id);


--
-- Name: idx_realm_def_grp_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_def_grp_realm ON public.realm_default_groups USING btree (realm_id);


--
-- Name: idx_realm_def_roles_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_def_roles_realm ON public.realm_default_roles USING btree (realm_id);


--
-- Name: idx_realm_evt_list_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_evt_list_realm ON public.realm_events_listeners USING btree (realm_id);


--
-- Name: idx_realm_evt_types_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_evt_types_realm ON public.realm_enabled_event_types USING btree (realm_id);


--
-- Name: idx_realm_master_adm_cli; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_master_adm_cli ON public.realm USING btree (master_admin_client);


--
-- Name: idx_realm_supp_local_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_supp_local_realm ON public.realm_supported_locales USING btree (realm_id);


--
-- Name: idx_redir_uri_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_redir_uri_client ON public.redirect_uris USING btree (client_id);


--
-- Name: idx_req_act_prov_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_req_act_prov_realm ON public.required_action_provider USING btree (realm_id);


--
-- Name: idx_res_policy_policy; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_policy_policy ON public.resource_policy USING btree (policy_id);


--
-- Name: idx_res_scope_scope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_scope_scope ON public.resource_scope USING btree (scope_id);


--
-- Name: idx_res_serv_pol_res_serv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_serv_pol_res_serv ON public.resource_server_policy USING btree (resource_server_id);


--
-- Name: idx_res_srv_res_res_srv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_srv_res_res_srv ON public.resource_server_resource USING btree (resource_server_id);


--
-- Name: idx_res_srv_scope_res_srv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_srv_scope_res_srv ON public.resource_server_scope USING btree (resource_server_id);


--
-- Name: idx_role_attribute; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_role_attribute ON public.role_attribute USING btree (role_id);


--
-- Name: idx_role_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_role_clscope ON public.client_scope_role_mapping USING btree (role_id);


--
-- Name: idx_scope_mapping_role; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_scope_mapping_role ON public.scope_mapping USING btree (role_id);


--
-- Name: idx_scope_policy_policy; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_scope_policy_policy ON public.scope_policy USING btree (policy_id);


--
-- Name: idx_us_sess_id_on_cl_sess; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_us_sess_id_on_cl_sess ON public.offline_client_session USING btree (user_session_id);


--
-- Name: idx_usconsent_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usconsent_clscope ON public.user_consent_client_scope USING btree (user_consent_id);


--
-- Name: idx_user_attribute; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_attribute ON public.user_attribute USING btree (user_id);


--
-- Name: idx_user_consent; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_consent ON public.user_consent USING btree (user_id);


--
-- Name: idx_user_credential; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_credential ON public.credential USING btree (user_id);


--
-- Name: idx_user_email; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_email ON public.user_entity USING btree (email);


--
-- Name: idx_user_group_mapping; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_group_mapping ON public.user_group_membership USING btree (user_id);


--
-- Name: idx_user_reqactions; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_reqactions ON public.user_required_action USING btree (user_id);


--
-- Name: idx_user_role_mapping; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_role_mapping ON public.user_role_mapping USING btree (user_id);


--
-- Name: idx_usr_fed_map_fed_prv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usr_fed_map_fed_prv ON public.user_federation_mapper USING btree (federation_provider_id);


--
-- Name: idx_usr_fed_map_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usr_fed_map_realm ON public.user_federation_mapper USING btree (realm_id);


--
-- Name: idx_usr_fed_prv_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usr_fed_prv_realm ON public.user_federation_provider USING btree (realm_id);


--
-- Name: idx_web_orig_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_web_orig_client ON public.web_origins USING btree (client_id);


--
-- Name: client_session_auth_status auth_status_constraint; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_auth_status
    ADD CONSTRAINT auth_status_constraint FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: identity_provider fk2b4ebc52ae5c3b34; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT fk2b4ebc52ae5c3b34 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_attributes fk3c47c64beacca966; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT fk3c47c64beacca966 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: federated_identity fk404288b92ef007a6; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT fk404288b92ef007a6 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_node_registrations fk4129723ba992f594; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT fk4129723ba992f594 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_session_note fk5edfb00ff51c2736; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_note
    ADD CONSTRAINT fk5edfb00ff51c2736 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: user_session_note fk5edfb00ff51d3472; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_session_note
    ADD CONSTRAINT fk5edfb00ff51d3472 FOREIGN KEY (user_session) REFERENCES public.user_session(id);


--
-- Name: client_session_role fk_11b7sgqw18i532811v7o2dv76; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_role
    ADD CONSTRAINT fk_11b7sgqw18i532811v7o2dv76 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: redirect_uris fk_1burs8pb4ouj97h5wuppahv9f; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT fk_1burs8pb4ouj97h5wuppahv9f FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: user_federation_provider fk_1fj32f6ptolw2qy60cd8n01e8; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT fk_1fj32f6ptolw2qy60cd8n01e8 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_session_prot_mapper fk_33a8sgqw18i532811v7o2dk89; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_prot_mapper
    ADD CONSTRAINT fk_33a8sgqw18i532811v7o2dk89 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: realm_required_credential fk_5hg65lybevavkqfki3kponh9v; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT fk_5hg65lybevavkqfki3kponh9v FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_attribute fk_5hrm2vlf9ql5fu022kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu022kqepovbr FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: user_attribute fk_5hrm2vlf9ql5fu043kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu043kqepovbr FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: user_required_action fk_6qj3w1jw9cvafhe19bwsiuvmd; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT fk_6qj3w1jw9cvafhe19bwsiuvmd FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: keycloak_role fk_6vyqfe4cn4wlq8r6kt5vdsj5c; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_6vyqfe4cn4wlq8r6kt5vdsj5c FOREIGN KEY (realm) REFERENCES public.realm(id);


--
-- Name: realm_smtp_config fk_70ej8xdxgxd0b9hh6180irr0o; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT fk_70ej8xdxgxd0b9hh6180irr0o FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_default_roles fk_8aelwnibji49avxsrtuf6xjow; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT fk_8aelwnibji49avxsrtuf6xjow FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_attribute fk_8shxd6l3e9atqukacxgpffptw; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT fk_8shxd6l3e9atqukacxgpffptw FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: composite_role fk_a63wvekftu8jo1pnj81e7mce2; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_a63wvekftu8jo1pnj81e7mce2 FOREIGN KEY (composite) REFERENCES public.keycloak_role(id);


--
-- Name: authentication_execution fk_auth_exec_flow; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_flow FOREIGN KEY (flow_id) REFERENCES public.authentication_flow(id);


--
-- Name: authentication_execution fk_auth_exec_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authentication_flow fk_auth_flow_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT fk_auth_flow_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authenticator_config fk_auth_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT fk_auth_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_session fk_b4ao2vcvat6ukau74wbwtfqo1; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session
    ADD CONSTRAINT fk_b4ao2vcvat6ukau74wbwtfqo1 FOREIGN KEY (session_id) REFERENCES public.user_session(id);


--
-- Name: user_role_mapping fk_c4fqv34p1mbylloxang7b1q3l; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT fk_c4fqv34p1mbylloxang7b1q3l FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_scope_client fk_c_cli_scope_client; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT fk_c_cli_scope_client FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_scope_client fk_c_cli_scope_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT fk_c_cli_scope_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_attributes fk_cl_scope_attr_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT fk_cl_scope_attr_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_role; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_role FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_user_session_note fk_cl_usr_ses_note; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_user_session_note
    ADD CONSTRAINT fk_cl_usr_ses_note FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: protocol_mapper fk_cli_scope_mapper; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_cli_scope_mapper FOREIGN KEY (client_scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_initial_access fk_client_init_acc_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT fk_client_init_acc_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: component_config fk_component_config; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT fk_component_config FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: component fk_component_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT fk_component_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: credential_attribute fk_cred_attr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential_attribute
    ADD CONSTRAINT fk_cred_attr FOREIGN KEY (credential_id) REFERENCES public.credential(id);


--
-- Name: realm_default_groups fk_def_groups_group; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: realm_default_groups fk_def_groups_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_default_roles fk_evudb1ppw84oxfax2drs03icc; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT fk_evudb1ppw84oxfax2drs03icc FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: fed_credential_attribute fk_fed_cred_attr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_credential_attribute
    ADD CONSTRAINT fk_fed_cred_attr FOREIGN KEY (credential_id) REFERENCES public.fed_user_credential(id);


--
-- Name: user_federation_mapper_config fk_fedmapper_cfg; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT fk_fedmapper_cfg FOREIGN KEY (user_federation_mapper_id) REFERENCES public.user_federation_mapper(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_fedprv; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_fedprv FOREIGN KEY (federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: associated_policy fk_frsr5s213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsr5s213xcx4wnkog82ssrfy FOREIGN KEY (associated_policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrasp13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrasp13xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog82sspmt; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82sspmt FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_resource fk_frsrho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog83sspmt; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog83sspmt FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog84sspmt; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog84sspmt FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: associated_policy fk_frsrpas14xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsrpas14xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrpass3xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrpass3xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_perm_ticket fk_frsrpo2128cx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrpo2128cx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_policy fk_frsrpo213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT fk_frsrpo213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_scope fk_frsrpos13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrpos13xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpos53xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpos53xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpp213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpp213xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_scope fk_frsrps213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrps213xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_scope fk_frsrso213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT fk_frsrso213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: composite_role fk_gr7thllb9lu8q4vqa4524jjy8; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_gr7thllb9lu8q4vqa4524jjy8 FOREIGN KEY (child_role) REFERENCES public.keycloak_role(id);


--
-- Name: user_consent_client_scope fk_grntcsnt_clsc_usc; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT fk_grntcsnt_clsc_usc FOREIGN KEY (user_consent_id) REFERENCES public.user_consent(id);


--
-- Name: user_consent fk_grntcsnt_user; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT fk_grntcsnt_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: group_attribute fk_group_attribute_group; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT fk_group_attribute_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: keycloak_group fk_group_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT fk_group_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: group_role_mapping fk_group_role_group; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: group_role_mapping fk_group_role_role; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_role FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_default_roles fk_h4wpd7w4hsoolni3h0sw7btje; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT fk_h4wpd7w4hsoolni3h0sw7btje FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_enabled_event_types fk_h846o4h0w8epx5nwedrf5y69j; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT fk_h846o4h0w8epx5nwedrf5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_events_listeners fk_h846o4h0w8epx5nxev9f5y69j; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT fk_h846o4h0w8epx5nxev9f5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: identity_provider_mapper fk_idpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT fk_idpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: idp_mapper_config fk_idpmconfig; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT fk_idpmconfig FOREIGN KEY (idp_mapper_id) REFERENCES public.identity_provider_mapper(id);


--
-- Name: keycloak_role fk_kjho5le2c0ral09fl8cm9wfw9; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_kjho5le2c0ral09fl8cm9wfw9 FOREIGN KEY (client) REFERENCES public.client(id);


--
-- Name: web_origins fk_lojpho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT fk_lojpho213xcx4wnkog82ssrfy FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_default_roles fk_nuilts7klwqw2h8m2b5joytky; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT fk_nuilts7klwqw2h8m2b5joytky FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: scope_mapping fk_ouse064plmlr732lxjcn1q5f1; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_ouse064plmlr732lxjcn1q5f1 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: scope_mapping fk_p3rh9grku11kqfrs4fltt7rnq; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_p3rh9grku11kqfrs4fltt7rnq FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: client fk_p56ctinxxb9gsk57fo49f9tac; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT fk_p56ctinxxb9gsk57fo49f9tac FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: protocol_mapper fk_pcm_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_pcm_realm FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: credential fk_pfyr0glasqyl0dei3kl69r6v0; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT fk_pfyr0glasqyl0dei3kl69r6v0 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: protocol_mapper_config fk_pmconfig; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT fk_pmconfig FOREIGN KEY (protocol_mapper_id) REFERENCES public.protocol_mapper(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope fk_realm_cli_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT fk_realm_cli_scope FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: required_action_provider fk_req_act_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT fk_req_act_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_uris fk_resource_server_uris; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT fk_resource_server_uris FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: role_attribute fk_role_attribute_id; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT fk_role_attribute_id FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_supported_locales fk_supported_locales_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT fk_supported_locales_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_federation_config fk_t13hpu1j94r2ebpekr39x5eu5; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT fk_t13hpu1j94r2ebpekr39x5eu5 FOREIGN KEY (user_federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: realm fk_traf444kk6qrkms7n56aiwq5y; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT fk_traf444kk6qrkms7n56aiwq5y FOREIGN KEY (master_admin_client) REFERENCES public.client(id);


--
-- Name: user_group_membership fk_user_group_user; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT fk_user_group_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: policy_config fkdc34197cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT fkdc34197cf864c4e43 FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: identity_provider_config fkdc4897cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT fkdc4897cf864c4e43 FOREIGN KEY (identity_provider_id) REFERENCES public.identity_provider(internal_id);


--
-- PostgreSQL database dump complete
--

\connect oidc

SET default_transaction_read_only = off;

--
-- PostgreSQL database dump
--

-- Dumped from database version 10.4
-- Dumped by pg_dump version 10.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: admin_event_entity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.admin_event_entity (
    id character varying(36) NOT NULL,
    admin_event_time bigint,
    realm_id character varying(255),
    operation_type character varying(255),
    auth_realm_id character varying(255),
    auth_client_id character varying(255),
    auth_user_id character varying(255),
    ip_address character varying(255),
    resource_path character varying(2550),
    representation text,
    error character varying(255),
    resource_type character varying(64)
);


ALTER TABLE public.admin_event_entity OWNER TO dbuser;

--
-- Name: associated_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.associated_policy (
    policy_id character varying(36) NOT NULL,
    associated_policy_id character varying(36) NOT NULL
);


ALTER TABLE public.associated_policy OWNER TO dbuser;

--
-- Name: authentication_execution; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authentication_execution (
    id character varying(36) NOT NULL,
    alias character varying(255),
    authenticator character varying(36),
    realm_id character varying(36),
    flow_id character varying(36),
    requirement integer,
    priority integer,
    authenticator_flow boolean DEFAULT false NOT NULL,
    auth_flow_id character varying(36),
    auth_config character varying(36)
);


ALTER TABLE public.authentication_execution OWNER TO dbuser;

--
-- Name: authentication_flow; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authentication_flow (
    id character varying(36) NOT NULL,
    alias character varying(255),
    description character varying(255),
    realm_id character varying(36),
    provider_id character varying(36) DEFAULT 'basic-flow'::character varying NOT NULL,
    top_level boolean DEFAULT false NOT NULL,
    built_in boolean DEFAULT false NOT NULL
);


ALTER TABLE public.authentication_flow OWNER TO dbuser;

--
-- Name: authenticator_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authenticator_config (
    id character varying(36) NOT NULL,
    alias character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.authenticator_config OWNER TO dbuser;

--
-- Name: authenticator_config_entry; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.authenticator_config_entry (
    authenticator_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.authenticator_config_entry OWNER TO dbuser;

--
-- Name: broker_link; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.broker_link (
    identity_provider character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL,
    broker_user_id character varying(255),
    broker_username character varying(255),
    token text,
    user_id character varying(255) NOT NULL
);


ALTER TABLE public.broker_link OWNER TO dbuser;

--
-- Name: client; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client (
    id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    full_scope_allowed boolean DEFAULT false NOT NULL,
    client_id character varying(255),
    not_before integer,
    public_client boolean DEFAULT false NOT NULL,
    secret character varying(255),
    base_url character varying(255),
    bearer_only boolean DEFAULT false NOT NULL,
    management_url character varying(255),
    surrogate_auth_required boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    protocol character varying(255),
    node_rereg_timeout integer DEFAULT 0,
    frontchannel_logout boolean DEFAULT false NOT NULL,
    consent_required boolean DEFAULT false NOT NULL,
    name character varying(255),
    service_accounts_enabled boolean DEFAULT false NOT NULL,
    client_authenticator_type character varying(255),
    root_url character varying(255),
    description character varying(255),
    registration_token character varying(255),
    standard_flow_enabled boolean DEFAULT true NOT NULL,
    implicit_flow_enabled boolean DEFAULT false NOT NULL,
    direct_access_grants_enabled boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client OWNER TO dbuser;

--
-- Name: client_attributes; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_attributes (
    client_id character varying(36) NOT NULL,
    value character varying(4000),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_attributes OWNER TO dbuser;

--
-- Name: client_auth_flow_bindings; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_auth_flow_bindings (
    client_id character varying(36) NOT NULL,
    flow_id character varying(36),
    binding_name character varying(255) NOT NULL
);


ALTER TABLE public.client_auth_flow_bindings OWNER TO dbuser;

--
-- Name: client_default_roles; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_default_roles (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_default_roles OWNER TO dbuser;

--
-- Name: client_initial_access; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_initial_access (
    id character varying(36) NOT NULL,
    realm_id character varying(36) NOT NULL,
    "timestamp" integer,
    expiration integer,
    count integer,
    remaining_count integer
);


ALTER TABLE public.client_initial_access OWNER TO dbuser;

--
-- Name: client_node_registrations; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_node_registrations (
    client_id character varying(36) NOT NULL,
    value integer,
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_node_registrations OWNER TO dbuser;

--
-- Name: client_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope (
    id character varying(36) NOT NULL,
    name character varying(255),
    realm_id character varying(36),
    description character varying(255),
    protocol character varying(255)
);


ALTER TABLE public.client_scope OWNER TO dbuser;

--
-- Name: client_scope_attributes; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope_attributes (
    scope_id character varying(36) NOT NULL,
    value character varying(2048),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_scope_attributes OWNER TO dbuser;

--
-- Name: client_scope_client; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope_client (
    client_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client_scope_client OWNER TO dbuser;

--
-- Name: client_scope_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_scope_role_mapping (
    scope_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_scope_role_mapping OWNER TO dbuser;

--
-- Name: client_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    redirect_uri character varying(255),
    state character varying(255),
    "timestamp" integer,
    session_id character varying(36),
    auth_method character varying(255),
    realm_id character varying(255),
    auth_user_id character varying(36),
    current_action character varying(36)
);


ALTER TABLE public.client_session OWNER TO dbuser;

--
-- Name: client_session_auth_status; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_auth_status (
    authenticator character varying(36) NOT NULL,
    status integer,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_auth_status OWNER TO dbuser;

--
-- Name: client_session_note; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_note (
    name character varying(255) NOT NULL,
    value character varying(255),
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_note OWNER TO dbuser;

--
-- Name: client_session_prot_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_prot_mapper (
    protocol_mapper_id character varying(36) NOT NULL,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_prot_mapper OWNER TO dbuser;

--
-- Name: client_session_role; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_session_role (
    role_id character varying(255) NOT NULL,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_role OWNER TO dbuser;

--
-- Name: client_user_session_note; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.client_user_session_note (
    name character varying(255) NOT NULL,
    value character varying(2048),
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_user_session_note OWNER TO dbuser;

--
-- Name: component; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.component (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_id character varying(36),
    provider_id character varying(36),
    provider_type character varying(255),
    realm_id character varying(36),
    sub_type character varying(255)
);


ALTER TABLE public.component OWNER TO dbuser;

--
-- Name: component_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.component_config (
    id character varying(36) NOT NULL,
    component_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.component_config OWNER TO dbuser;

--
-- Name: composite_role; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.composite_role (
    composite character varying(36) NOT NULL,
    child_role character varying(36) NOT NULL
);


ALTER TABLE public.composite_role OWNER TO dbuser;

--
-- Name: credential; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.credential (
    id character varying(36) NOT NULL,
    device character varying(255),
    hash_iterations integer,
    salt bytea,
    type character varying(255),
    value character varying(4000),
    user_id character varying(36),
    created_date bigint,
    counter integer DEFAULT 0,
    digits integer DEFAULT 6,
    period integer DEFAULT 30,
    algorithm character varying(36) DEFAULT NULL::character varying
);


ALTER TABLE public.credential OWNER TO dbuser;

--
-- Name: credential_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.credential_attribute (
    id character varying(36) NOT NULL,
    credential_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.credential_attribute OWNER TO dbuser;

--
-- Name: databasechangelog; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.databasechangelog (
    id character varying(255) NOT NULL,
    author character varying(255) NOT NULL,
    filename character varying(255) NOT NULL,
    dateexecuted timestamp without time zone NOT NULL,
    orderexecuted integer NOT NULL,
    exectype character varying(10) NOT NULL,
    md5sum character varying(35),
    description character varying(255),
    comments character varying(255),
    tag character varying(255),
    liquibase character varying(20),
    contexts character varying(255),
    labels character varying(255),
    deployment_id character varying(10)
);


ALTER TABLE public.databasechangelog OWNER TO dbuser;

--
-- Name: databasechangeloglock; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.databasechangeloglock (
    id integer NOT NULL,
    locked boolean NOT NULL,
    lockgranted timestamp without time zone,
    lockedby character varying(255)
);


ALTER TABLE public.databasechangeloglock OWNER TO dbuser;

--
-- Name: default_client_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.default_client_scope (
    realm_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.default_client_scope OWNER TO dbuser;

--
-- Name: event_entity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.event_entity (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    details_json character varying(2550),
    error character varying(255),
    ip_address character varying(255),
    realm_id character varying(255),
    session_id character varying(255),
    event_time bigint,
    type character varying(255),
    user_id character varying(255)
);


ALTER TABLE public.event_entity OWNER TO dbuser;

--
-- Name: fed_credential_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_credential_attribute (
    id character varying(36) NOT NULL,
    credential_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.fed_credential_attribute OWNER TO dbuser;

--
-- Name: fed_user_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_attribute (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    value character varying(2024)
);


ALTER TABLE public.fed_user_attribute OWNER TO dbuser;

--
-- Name: fed_user_consent; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.fed_user_consent OWNER TO dbuser;

--
-- Name: fed_user_consent_cl_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_consent_cl_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.fed_user_consent_cl_scope OWNER TO dbuser;

--
-- Name: fed_user_credential; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_credential (
    id character varying(36) NOT NULL,
    device character varying(255),
    hash_iterations integer,
    salt bytea,
    type character varying(255),
    value character varying(255),
    created_date bigint,
    counter integer DEFAULT 0,
    digits integer DEFAULT 6,
    period integer DEFAULT 30,
    algorithm character varying(36) DEFAULT 'HmacSHA1'::character varying,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_credential OWNER TO dbuser;

--
-- Name: fed_user_group_membership; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_group_membership OWNER TO dbuser;

--
-- Name: fed_user_required_action; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_required_action (
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_required_action OWNER TO dbuser;

--
-- Name: fed_user_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.fed_user_role_mapping (
    role_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_role_mapping OWNER TO dbuser;

--
-- Name: federated_identity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.federated_identity (
    identity_provider character varying(255) NOT NULL,
    realm_id character varying(36),
    federated_user_id character varying(255),
    federated_username character varying(255),
    token text,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_identity OWNER TO dbuser;

--
-- Name: federated_user; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.federated_user (
    id character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_user OWNER TO dbuser;

--
-- Name: group_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.group_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_attribute OWNER TO dbuser;

--
-- Name: group_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.group_role_mapping (
    role_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_role_mapping OWNER TO dbuser;

--
-- Name: identity_provider; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.identity_provider (
    internal_id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    provider_alias character varying(255),
    provider_id character varying(255),
    store_token boolean DEFAULT false NOT NULL,
    authenticate_by_default boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    add_token_role boolean DEFAULT true NOT NULL,
    trust_email boolean DEFAULT false NOT NULL,
    first_broker_login_flow_id character varying(36),
    post_broker_login_flow_id character varying(36),
    provider_display_name character varying(255),
    link_only boolean DEFAULT false NOT NULL
);


ALTER TABLE public.identity_provider OWNER TO dbuser;

--
-- Name: identity_provider_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.identity_provider_config (
    identity_provider_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.identity_provider_config OWNER TO dbuser;

--
-- Name: identity_provider_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.identity_provider_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    idp_alias character varying(255) NOT NULL,
    idp_mapper_name character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.identity_provider_mapper OWNER TO dbuser;

--
-- Name: idp_mapper_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.idp_mapper_config (
    idp_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.idp_mapper_config OWNER TO dbuser;

--
-- Name: keycloak_group; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.keycloak_group (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_group character varying(36),
    realm_id character varying(36)
);


ALTER TABLE public.keycloak_group OWNER TO dbuser;

--
-- Name: keycloak_role; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.keycloak_role (
    id character varying(36) NOT NULL,
    client_realm_constraint character varying(36),
    client_role boolean DEFAULT false NOT NULL,
    description character varying(255),
    name character varying(255),
    realm_id character varying(255),
    client character varying(36),
    realm character varying(36)
);


ALTER TABLE public.keycloak_role OWNER TO dbuser;

--
-- Name: migration_model; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.migration_model (
    id character varying(36) NOT NULL,
    version character varying(36)
);


ALTER TABLE public.migration_model OWNER TO dbuser;

--
-- Name: offline_client_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.offline_client_session (
    user_session_id character varying(36) NOT NULL,
    client_id character varying(36) NOT NULL,
    offline_flag character varying(4) NOT NULL,
    "timestamp" integer,
    data text,
    client_storage_provider character varying(36) DEFAULT 'local'::character varying NOT NULL,
    external_client_id character varying(255) DEFAULT 'local'::character varying NOT NULL
);


ALTER TABLE public.offline_client_session OWNER TO dbuser;

--
-- Name: offline_user_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.offline_user_session (
    user_session_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    created_on integer NOT NULL,
    offline_flag character varying(4) NOT NULL,
    data text,
    last_session_refresh integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.offline_user_session OWNER TO dbuser;

--
-- Name: policy_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.policy_config (
    policy_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.policy_config OWNER TO dbuser;

--
-- Name: protocol_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.protocol_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    protocol character varying(255) NOT NULL,
    protocol_mapper_name character varying(255) NOT NULL,
    client_id character varying(36),
    client_scope_id character varying(36)
);


ALTER TABLE public.protocol_mapper OWNER TO dbuser;

--
-- Name: protocol_mapper_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.protocol_mapper_config (
    protocol_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.protocol_mapper_config OWNER TO dbuser;

--
-- Name: realm; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm (
    id character varying(36) NOT NULL,
    access_code_lifespan integer,
    user_action_lifespan integer,
    access_token_lifespan integer,
    account_theme character varying(255),
    admin_theme character varying(255),
    email_theme character varying(255),
    enabled boolean DEFAULT false NOT NULL,
    events_enabled boolean DEFAULT false NOT NULL,
    events_expiration bigint,
    login_theme character varying(255),
    name character varying(255),
    not_before integer,
    password_policy character varying(2550),
    registration_allowed boolean DEFAULT false NOT NULL,
    remember_me boolean DEFAULT false NOT NULL,
    reset_password_allowed boolean DEFAULT false NOT NULL,
    social boolean DEFAULT false NOT NULL,
    ssl_required character varying(255),
    sso_idle_timeout integer,
    sso_max_lifespan integer,
    update_profile_on_soc_login boolean DEFAULT false NOT NULL,
    verify_email boolean DEFAULT false NOT NULL,
    master_admin_client character varying(36),
    login_lifespan integer,
    internationalization_enabled boolean DEFAULT false NOT NULL,
    default_locale character varying(255),
    reg_email_as_username boolean DEFAULT false NOT NULL,
    admin_events_enabled boolean DEFAULT false NOT NULL,
    admin_events_details_enabled boolean DEFAULT false NOT NULL,
    edit_username_allowed boolean DEFAULT false NOT NULL,
    otp_policy_counter integer DEFAULT 0,
    otp_policy_window integer DEFAULT 1,
    otp_policy_period integer DEFAULT 30,
    otp_policy_digits integer DEFAULT 6,
    otp_policy_alg character varying(36) DEFAULT 'HmacSHA1'::character varying,
    otp_policy_type character varying(36) DEFAULT 'totp'::character varying,
    browser_flow character varying(36),
    registration_flow character varying(36),
    direct_grant_flow character varying(36),
    reset_credentials_flow character varying(36),
    client_auth_flow character varying(36),
    offline_session_idle_timeout integer DEFAULT 0,
    revoke_refresh_token boolean DEFAULT false NOT NULL,
    access_token_life_implicit integer DEFAULT 0,
    login_with_email_allowed boolean DEFAULT true NOT NULL,
    duplicate_emails_allowed boolean DEFAULT false NOT NULL,
    docker_auth_flow character varying(36),
    refresh_token_max_reuse integer DEFAULT 0,
    allow_user_managed_access boolean DEFAULT false NOT NULL,
    sso_max_lifespan_remember_me integer DEFAULT 0 NOT NULL,
    sso_idle_timeout_remember_me integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.realm OWNER TO dbuser;

--
-- Name: realm_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_attribute OWNER TO dbuser;

--
-- Name: realm_default_groups; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_default_groups (
    realm_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_groups OWNER TO dbuser;

--
-- Name: realm_default_roles; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_default_roles (
    realm_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_roles OWNER TO dbuser;

--
-- Name: realm_enabled_event_types; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_enabled_event_types (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_enabled_event_types OWNER TO dbuser;

--
-- Name: realm_events_listeners; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_events_listeners (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_events_listeners OWNER TO dbuser;

--
-- Name: realm_required_credential; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_required_credential (
    type character varying(255) NOT NULL,
    form_label character varying(255),
    input boolean DEFAULT false NOT NULL,
    secret boolean DEFAULT false NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_required_credential OWNER TO dbuser;

--
-- Name: realm_smtp_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_smtp_config (
    realm_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.realm_smtp_config OWNER TO dbuser;

--
-- Name: realm_supported_locales; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.realm_supported_locales (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_supported_locales OWNER TO dbuser;

--
-- Name: redirect_uris; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.redirect_uris (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.redirect_uris OWNER TO dbuser;

--
-- Name: required_action_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.required_action_config (
    required_action_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.required_action_config OWNER TO dbuser;

--
-- Name: required_action_provider; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.required_action_provider (
    id character varying(36) NOT NULL,
    alias character varying(255),
    name character varying(255),
    realm_id character varying(36),
    enabled boolean DEFAULT false NOT NULL,
    default_action boolean DEFAULT false NOT NULL,
    provider_id character varying(255),
    priority integer
);


ALTER TABLE public.required_action_provider OWNER TO dbuser;

--
-- Name: resource_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    resource_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_attribute OWNER TO dbuser;

--
-- Name: resource_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_policy (
    resource_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_policy OWNER TO dbuser;

--
-- Name: resource_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_scope (
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_scope OWNER TO dbuser;

--
-- Name: resource_server; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server (
    id character varying(36) NOT NULL,
    allow_rs_remote_mgmt boolean DEFAULT false NOT NULL,
    policy_enforce_mode character varying(15) NOT NULL
);


ALTER TABLE public.resource_server OWNER TO dbuser;

--
-- Name: resource_server_perm_ticket; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_perm_ticket (
    id character varying(36) NOT NULL,
    owner character varying(36) NOT NULL,
    requester character varying(36) NOT NULL,
    created_timestamp bigint NOT NULL,
    granted_timestamp bigint,
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36),
    resource_server_id character varying(36) NOT NULL,
    policy_id character varying(36)
);


ALTER TABLE public.resource_server_perm_ticket OWNER TO dbuser;

--
-- Name: resource_server_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_policy (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255),
    type character varying(255) NOT NULL,
    decision_strategy character varying(20),
    logic character varying(20),
    resource_server_id character varying(36) NOT NULL,
    owner character varying(36)
);


ALTER TABLE public.resource_server_policy OWNER TO dbuser;

--
-- Name: resource_server_resource; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_resource (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    type character varying(255),
    icon_uri character varying(255),
    owner character varying(36) NOT NULL,
    resource_server_id character varying(36) NOT NULL,
    owner_managed_access boolean DEFAULT false NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_resource OWNER TO dbuser;

--
-- Name: resource_server_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_server_scope (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    icon_uri character varying(255),
    resource_server_id character varying(36) NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_scope OWNER TO dbuser;

--
-- Name: resource_uris; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.resource_uris (
    resource_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.resource_uris OWNER TO dbuser;

--
-- Name: role_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.role_attribute (
    id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255)
);


ALTER TABLE public.role_attribute OWNER TO dbuser;

--
-- Name: scope_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.scope_mapping (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_mapping OWNER TO dbuser;

--
-- Name: scope_policy; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.scope_policy (
    scope_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_policy OWNER TO dbuser;

--
-- Name: user_attribute; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    user_id character varying(36) NOT NULL,
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL
);


ALTER TABLE public.user_attribute OWNER TO dbuser;

--
-- Name: user_consent; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    user_id character varying(36) NOT NULL,
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.user_consent OWNER TO dbuser;

--
-- Name: user_consent_client_scope; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_consent_client_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.user_consent_client_scope OWNER TO dbuser;

--
-- Name: user_entity; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_entity (
    id character varying(36) NOT NULL,
    email character varying(255),
    email_constraint character varying(255),
    email_verified boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    federation_link character varying(255),
    first_name character varying(255),
    last_name character varying(255),
    realm_id character varying(255),
    username character varying(255),
    created_timestamp bigint,
    service_account_client_link character varying(36),
    not_before integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.user_entity OWNER TO dbuser;

--
-- Name: user_federation_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_config (
    user_federation_provider_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_config OWNER TO dbuser;

--
-- Name: user_federation_mapper; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    federation_provider_id character varying(36) NOT NULL,
    federation_mapper_type character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.user_federation_mapper OWNER TO dbuser;

--
-- Name: user_federation_mapper_config; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_mapper_config (
    user_federation_mapper_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_mapper_config OWNER TO dbuser;

--
-- Name: user_federation_provider; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_federation_provider (
    id character varying(36) NOT NULL,
    changed_sync_period integer,
    display_name character varying(255),
    full_sync_period integer,
    last_sync integer,
    priority integer,
    provider_name character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.user_federation_provider OWNER TO dbuser;

--
-- Name: user_group_membership; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_group_membership OWNER TO dbuser;

--
-- Name: user_required_action; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_required_action (
    user_id character varying(36) NOT NULL,
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL
);


ALTER TABLE public.user_required_action OWNER TO dbuser;

--
-- Name: user_role_mapping; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_role_mapping (
    role_id character varying(255) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_role_mapping OWNER TO dbuser;

--
-- Name: user_session; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_session (
    id character varying(36) NOT NULL,
    auth_method character varying(255),
    ip_address character varying(255),
    last_session_refresh integer,
    login_username character varying(255),
    realm_id character varying(255),
    remember_me boolean DEFAULT false NOT NULL,
    started integer,
    user_id character varying(255),
    user_session_state integer,
    broker_session_id character varying(255),
    broker_user_id character varying(255)
);


ALTER TABLE public.user_session OWNER TO dbuser;

--
-- Name: user_session_note; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.user_session_note (
    user_session character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(2048)
);


ALTER TABLE public.user_session_note OWNER TO dbuser;

--
-- Name: username_login_failure; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.username_login_failure (
    realm_id character varying(36) NOT NULL,
    username character varying(255) NOT NULL,
    failed_login_not_before integer,
    last_failure bigint,
    last_ip_failure character varying(255),
    num_failures integer
);


ALTER TABLE public.username_login_failure OWNER TO dbuser;

--
-- Name: web_origins; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.web_origins (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.web_origins OWNER TO dbuser;

--
-- Data for Name: admin_event_entity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.admin_event_entity (id, admin_event_time, realm_id, operation_type, auth_realm_id, auth_client_id, auth_user_id, ip_address, resource_path, representation, error, resource_type) FROM stdin;
\.


--
-- Data for Name: associated_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.associated_policy (policy_id, associated_policy_id) FROM stdin;
\.


--
-- Data for Name: authentication_execution; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authentication_execution (id, alias, authenticator, realm_id, flow_id, requirement, priority, authenticator_flow, auth_flow_id, auth_config) FROM stdin;
d239dd4b-6d10-44b9-9619-2d440a829685	\N	auth-cookie	master	3b20e7fd-478b-40ec-83dd-818940deeeee	2	10	f	\N	\N
c728a9a8-fcf8-4680-8c5d-670cf9bec025	\N	auth-spnego	master	3b20e7fd-478b-40ec-83dd-818940deeeee	3	20	f	\N	\N
7245b22f-0718-4d71-b19e-2e879219aed2	\N	identity-provider-redirector	master	3b20e7fd-478b-40ec-83dd-818940deeeee	2	25	f	\N	\N
454a6ae5-3739-4163-bd70-abd2b41deed4	\N	\N	master	3b20e7fd-478b-40ec-83dd-818940deeeee	2	30	t	767e0a57-7a61-46b7-a044-a205217b8444	\N
31a34eeb-6bf4-4ae0-94f3-1769c2bf55e1	\N	auth-username-password-form	master	767e0a57-7a61-46b7-a044-a205217b8444	0	10	f	\N	\N
d7e6382a-f944-4baf-8e0e-6c3240fb40fd	\N	auth-otp-form	master	767e0a57-7a61-46b7-a044-a205217b8444	1	20	f	\N	\N
c6d576f9-4fa3-4d43-828e-39531e859b44	\N	direct-grant-validate-username	master	0792121c-83a1-4d8e-9d11-6fdcfb4abdef	0	10	f	\N	\N
080b30ec-90f9-4d4f-9fe0-744f4b0bbe96	\N	direct-grant-validate-password	master	0792121c-83a1-4d8e-9d11-6fdcfb4abdef	0	20	f	\N	\N
8864a53c-50e3-43aa-ae46-ccbc68f29693	\N	direct-grant-validate-otp	master	0792121c-83a1-4d8e-9d11-6fdcfb4abdef	1	30	f	\N	\N
621bc230-8405-43ce-b99d-b0e3bf770d14	\N	registration-page-form	master	9f301b6f-1ca1-4296-bd33-7203097bf042	0	10	t	e0e07218-7343-4819-b561-b16de2e1ae8a	\N
716fdced-c3ed-47a0-865d-7f5625063f66	\N	registration-user-creation	master	e0e07218-7343-4819-b561-b16de2e1ae8a	0	20	f	\N	\N
5ed67af1-0f33-47d3-a584-851a234941e1	\N	registration-profile-action	master	e0e07218-7343-4819-b561-b16de2e1ae8a	0	40	f	\N	\N
4de513f4-3273-4e42-bdcb-5f09e4b78913	\N	registration-password-action	master	e0e07218-7343-4819-b561-b16de2e1ae8a	0	50	f	\N	\N
13ef4ab9-3e6d-495a-a9a1-c4119cec7a56	\N	registration-recaptcha-action	master	e0e07218-7343-4819-b561-b16de2e1ae8a	3	60	f	\N	\N
1d0d465d-fb4e-4552-b059-d3a221510866	\N	reset-credentials-choose-user	master	2fe63f14-bc2b-4284-8bdd-1e55aba0fd7d	0	10	f	\N	\N
eb3dfb2a-035b-4ad7-92d5-583263882e03	\N	reset-credential-email	master	2fe63f14-bc2b-4284-8bdd-1e55aba0fd7d	0	20	f	\N	\N
2ba409af-c061-466f-9394-da5d4e0982f9	\N	reset-password	master	2fe63f14-bc2b-4284-8bdd-1e55aba0fd7d	0	30	f	\N	\N
7447dabc-fb08-41ec-a328-611797288f64	\N	reset-otp	master	2fe63f14-bc2b-4284-8bdd-1e55aba0fd7d	1	40	f	\N	\N
0ffb28b5-618f-48bd-a14e-d22f56af02dc	\N	client-secret	master	5a7a0b79-3443-4924-85c3-97121f77915d	2	10	f	\N	\N
e543252d-9822-47de-b140-e81abd022ca5	\N	client-jwt	master	5a7a0b79-3443-4924-85c3-97121f77915d	2	20	f	\N	\N
1cc21f15-641e-4825-a96a-8c10ba3b2523	\N	client-secret-jwt	master	5a7a0b79-3443-4924-85c3-97121f77915d	2	30	f	\N	\N
8714b60e-9faa-4677-8d66-636db5efd314	\N	client-x509	master	5a7a0b79-3443-4924-85c3-97121f77915d	2	40	f	\N	\N
56140397-84bf-46a8-8220-8142e8fa4712	\N	idp-review-profile	master	9fbd83f5-838b-4678-bfe7-2f0edd275887	0	10	f	\N	8841220e-feca-4d94-af7a-470afa98e993
4197d7c9-26bf-4d17-a168-69e9795e2e2c	\N	idp-create-user-if-unique	master	9fbd83f5-838b-4678-bfe7-2f0edd275887	2	20	f	\N	d8c66658-3807-4246-9691-2703aa703ea4
40512d75-a766-41e0-8439-65ff7f827005	\N	\N	master	9fbd83f5-838b-4678-bfe7-2f0edd275887	2	30	t	e5c34e82-5ec0-4c96-8c54-64e1686b51fd	\N
9ad7b6af-5408-49f1-9938-ea45de550c92	\N	idp-confirm-link	master	e5c34e82-5ec0-4c96-8c54-64e1686b51fd	0	10	f	\N	\N
93ef3048-dfb2-411f-891a-5ddad96521ac	\N	idp-email-verification	master	e5c34e82-5ec0-4c96-8c54-64e1686b51fd	2	20	f	\N	\N
fc554940-26ff-404e-b78f-216787bfb346	\N	\N	master	e5c34e82-5ec0-4c96-8c54-64e1686b51fd	2	30	t	2e63e97d-6402-4a3d-a95b-902b24e73c51	\N
0e0ef36d-f7ec-4b66-bd98-3e40be0cb05a	\N	idp-username-password-form	master	2e63e97d-6402-4a3d-a95b-902b24e73c51	0	10	f	\N	\N
770f4082-cf9b-4830-9fb7-1e81402b5230	\N	auth-otp-form	master	2e63e97d-6402-4a3d-a95b-902b24e73c51	1	20	f	\N	\N
0de90049-8fd9-49fc-8ad9-44c355653a6d	\N	http-basic-authenticator	master	09485d97-cc90-4db2-9ad2-628a2aa3a943	0	10	f	\N	\N
0ef1844a-4bcd-4779-a6c7-b375fc6a11fe	\N	docker-http-basic-authenticator	master	4d694536-cbc9-4973-89c6-23bb91a2588a	0	10	f	\N	\N
c83a37bb-a00a-470b-bca6-ea456a2ba983	\N	no-cookie-redirect	master	f526a4e7-88e8-4c9a-a847-c985587d64a5	0	10	f	\N	\N
5c603e26-a639-4692-bfdf-eb5d4ed0392a	\N	basic-auth	master	f526a4e7-88e8-4c9a-a847-c985587d64a5	0	20	f	\N	\N
da54a0f6-0486-43d6-96ab-239b324a048b	\N	basic-auth-otp	master	f526a4e7-88e8-4c9a-a847-c985587d64a5	3	30	f	\N	\N
403e7506-4176-4202-a604-3ab510f41ebc	\N	auth-spnego	master	f526a4e7-88e8-4c9a-a847-c985587d64a5	3	40	f	\N	\N
\.


--
-- Data for Name: authentication_flow; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authentication_flow (id, alias, description, realm_id, provider_id, top_level, built_in) FROM stdin;
3b20e7fd-478b-40ec-83dd-818940deeeee	browser	browser based authentication	master	basic-flow	t	t
767e0a57-7a61-46b7-a044-a205217b8444	forms	Username, password, otp and other auth forms.	master	basic-flow	f	t
0792121c-83a1-4d8e-9d11-6fdcfb4abdef	direct grant	OpenID Connect Resource Owner Grant	master	basic-flow	t	t
9f301b6f-1ca1-4296-bd33-7203097bf042	registration	registration flow	master	basic-flow	t	t
e0e07218-7343-4819-b561-b16de2e1ae8a	registration form	registration form	master	form-flow	f	t
2fe63f14-bc2b-4284-8bdd-1e55aba0fd7d	reset credentials	Reset credentials for a user if they forgot their password or something	master	basic-flow	t	t
5a7a0b79-3443-4924-85c3-97121f77915d	clients	Base authentication for clients	master	client-flow	t	t
9fbd83f5-838b-4678-bfe7-2f0edd275887	first broker login	Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account	master	basic-flow	t	t
e5c34e82-5ec0-4c96-8c54-64e1686b51fd	Handle Existing Account	Handle what to do if there is existing account with same email/username like authenticated identity provider	master	basic-flow	f	t
2e63e97d-6402-4a3d-a95b-902b24e73c51	Verify Existing Account by Re-authentication	Reauthentication of existing account	master	basic-flow	f	t
09485d97-cc90-4db2-9ad2-628a2aa3a943	saml ecp	SAML ECP Profile Authentication Flow	master	basic-flow	t	t
4d694536-cbc9-4973-89c6-23bb91a2588a	docker auth	Used by Docker clients to authenticate against the IDP	master	basic-flow	t	t
f526a4e7-88e8-4c9a-a847-c985587d64a5	http challenge	An authentication flow based on challenge-response HTTP Authentication Schemes	master	basic-flow	t	t
\.


--
-- Data for Name: authenticator_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authenticator_config (id, alias, realm_id) FROM stdin;
8841220e-feca-4d94-af7a-470afa98e993	review profile config	master
d8c66658-3807-4246-9691-2703aa703ea4	create unique user config	master
\.


--
-- Data for Name: authenticator_config_entry; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.authenticator_config_entry (authenticator_id, value, name) FROM stdin;
8841220e-feca-4d94-af7a-470afa98e993	missing	update.profile.on.first.login
d8c66658-3807-4246-9691-2703aa703ea4	false	require.password.update.after.registration
\.


--
-- Data for Name: broker_link; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.broker_link (identity_provider, storage_provider_id, realm_id, broker_user_id, broker_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: client; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client (id, enabled, full_scope_allowed, client_id, not_before, public_client, secret, base_url, bearer_only, management_url, surrogate_auth_required, realm_id, protocol, node_rereg_timeout, frontchannel_logout, consent_required, name, service_accounts_enabled, client_authenticator_type, root_url, description, registration_token, standard_flow_enabled, implicit_flow_enabled, direct_access_grants_enabled) FROM stdin;
31531d43-30cf-4f40-8b04-2151b613e54a	t	t	master-realm	0	f	20c60390-c989-4482-9fdf-05302c4ba7d7	\N	t	\N	f	master	\N	0	f	f	master Realm	f	client-secret	\N	\N	\N	t	f	f
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	t	f	account	0	f	d0530fd0-334c-481e-809d-6efc7de95fbe	/auth/realms/master/account	f	\N	f	master	openid-connect	0	f	f	${client_account}	f	client-secret	\N	\N	\N	t	f	f
e865f20a-8b9f-49dd-84e3-f2b6b4468a55	t	f	broker	0	f	0035610c-ceae-45b7-b2dd-40f30fde598f	\N	f	\N	f	master	openid-connect	0	f	f	${client_broker}	f	client-secret	\N	\N	\N	t	f	f
7e747e82-a68b-46a8-a952-11e2b6f34a1b	t	f	security-admin-console	0	t	fbfaf46e-97b7-4e73-8caf-4a97d5e7935b	/auth/admin/master/console/index.html	f	\N	f	master	openid-connect	0	f	f	${client_security-admin-console}	f	client-secret	\N	\N	\N	t	f	f
91aad599-7aff-45b3-949c-21ce3d763581	t	f	admin-cli	0	t	ee398a9e-92e5-493b-91c7-a4898601f3ac	\N	f	\N	f	master	openid-connect	0	f	f	${client_admin-cli}	f	client-secret	\N	\N	\N	f	f	t
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	t	t	idp-flaminem	0	f	93002f5f-ad3f-4cde-8ee2-06f3f3a335cb	/broker/oidc-customer	f	\N	f	master	openid-connect	-1	f	f	OIDC SSO client for flaminem	f	client-secret	http://keycloak-flaminem.localtest.me:8080/auth/realms/master	\N	\N	t	f	f
\.


--
-- Data for Name: client_attributes; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_attributes (client_id, value, name) FROM stdin;
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	saml.server.signature
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	saml.server.signature.keyinfo.ext
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	saml.assertion.signature
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	saml.client.signature
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	saml.encrypt
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	saml.authnstatement
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	saml.onetimeuse.condition
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	saml_force_name_id_format
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	saml.multivalued.roles
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	saml.force.post.binding
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	exclude.session.state.from.auth.response
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	tls.client.certificate.bound.access.tokens
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	false	display.on.consent.screen
\.


--
-- Data for Name: client_auth_flow_bindings; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_auth_flow_bindings (client_id, flow_id, binding_name) FROM stdin;
\.


--
-- Data for Name: client_default_roles; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_default_roles (client_id, role_id) FROM stdin;
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	3e4f23ed-fc72-403f-a675-3e9641aeb1a6
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	43a803f1-931f-4c65-98b6-d741c5c00170
\.


--
-- Data for Name: client_initial_access; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_initial_access (id, realm_id, "timestamp", expiration, count, remaining_count) FROM stdin;
\.


--
-- Data for Name: client_node_registrations; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_node_registrations (client_id, value, name) FROM stdin;
\.


--
-- Data for Name: client_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope (id, name, realm_id, description, protocol) FROM stdin;
78fefb8f-ad2c-4087-bf86-1ac5db378034	offline_access	master	OpenID Connect built-in scope: offline_access	openid-connect
f806fc10-7e18-4823-8c40-e610cc7b3f52	role_list	master	SAML role list	saml
8580c6c6-4118-4bc8-8935-777a64d9de99	profile	master	OpenID Connect built-in scope: profile	openid-connect
920add0f-ae22-4b55-8494-283156626879	email	master	OpenID Connect built-in scope: email	openid-connect
99895a6e-497a-46cd-8b5d-a9a26344509f	address	master	OpenID Connect built-in scope: address	openid-connect
c25b82c3-20a8-45fb-976e-8160fb5a79b8	phone	master	OpenID Connect built-in scope: phone	openid-connect
1409bcea-a67b-4799-94b2-2543b59c9d45	roles	master	OpenID Connect scope for add user roles to the access token	openid-connect
81b5be5e-373c-47e0-ace8-299254218d88	web-origins	master	OpenID Connect scope for add allowed web origins to the access token	openid-connect
112556c8-d6c3-4620-a381-691d965c8165	microprofile-jwt	master	Microprofile - JWT built-in scope	openid-connect
\.


--
-- Data for Name: client_scope_attributes; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope_attributes (scope_id, value, name) FROM stdin;
78fefb8f-ad2c-4087-bf86-1ac5db378034	true	display.on.consent.screen
78fefb8f-ad2c-4087-bf86-1ac5db378034	${offlineAccessScopeConsentText}	consent.screen.text
f806fc10-7e18-4823-8c40-e610cc7b3f52	true	display.on.consent.screen
f806fc10-7e18-4823-8c40-e610cc7b3f52	${samlRoleListScopeConsentText}	consent.screen.text
8580c6c6-4118-4bc8-8935-777a64d9de99	true	display.on.consent.screen
8580c6c6-4118-4bc8-8935-777a64d9de99	${profileScopeConsentText}	consent.screen.text
8580c6c6-4118-4bc8-8935-777a64d9de99	true	include.in.token.scope
920add0f-ae22-4b55-8494-283156626879	true	display.on.consent.screen
920add0f-ae22-4b55-8494-283156626879	${emailScopeConsentText}	consent.screen.text
920add0f-ae22-4b55-8494-283156626879	true	include.in.token.scope
99895a6e-497a-46cd-8b5d-a9a26344509f	true	display.on.consent.screen
99895a6e-497a-46cd-8b5d-a9a26344509f	${addressScopeConsentText}	consent.screen.text
99895a6e-497a-46cd-8b5d-a9a26344509f	true	include.in.token.scope
c25b82c3-20a8-45fb-976e-8160fb5a79b8	true	display.on.consent.screen
c25b82c3-20a8-45fb-976e-8160fb5a79b8	${phoneScopeConsentText}	consent.screen.text
c25b82c3-20a8-45fb-976e-8160fb5a79b8	true	include.in.token.scope
1409bcea-a67b-4799-94b2-2543b59c9d45	true	display.on.consent.screen
1409bcea-a67b-4799-94b2-2543b59c9d45	${rolesScopeConsentText}	consent.screen.text
1409bcea-a67b-4799-94b2-2543b59c9d45	false	include.in.token.scope
81b5be5e-373c-47e0-ace8-299254218d88	false	display.on.consent.screen
81b5be5e-373c-47e0-ace8-299254218d88		consent.screen.text
81b5be5e-373c-47e0-ace8-299254218d88	false	include.in.token.scope
112556c8-d6c3-4620-a381-691d965c8165	false	display.on.consent.screen
112556c8-d6c3-4620-a381-691d965c8165	true	include.in.token.scope
\.


--
-- Data for Name: client_scope_client; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope_client (client_id, scope_id, default_scope) FROM stdin;
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	f806fc10-7e18-4823-8c40-e610cc7b3f52	t
91aad599-7aff-45b3-949c-21ce3d763581	f806fc10-7e18-4823-8c40-e610cc7b3f52	t
e865f20a-8b9f-49dd-84e3-f2b6b4468a55	f806fc10-7e18-4823-8c40-e610cc7b3f52	t
31531d43-30cf-4f40-8b04-2151b613e54a	f806fc10-7e18-4823-8c40-e610cc7b3f52	t
7e747e82-a68b-46a8-a952-11e2b6f34a1b	f806fc10-7e18-4823-8c40-e610cc7b3f52	t
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	8580c6c6-4118-4bc8-8935-777a64d9de99	t
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	920add0f-ae22-4b55-8494-283156626879	t
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	1409bcea-a67b-4799-94b2-2543b59c9d45	t
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	81b5be5e-373c-47e0-ace8-299254218d88	t
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	78fefb8f-ad2c-4087-bf86-1ac5db378034	f
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	99895a6e-497a-46cd-8b5d-a9a26344509f	f
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	c25b82c3-20a8-45fb-976e-8160fb5a79b8	f
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	112556c8-d6c3-4620-a381-691d965c8165	f
91aad599-7aff-45b3-949c-21ce3d763581	8580c6c6-4118-4bc8-8935-777a64d9de99	t
91aad599-7aff-45b3-949c-21ce3d763581	920add0f-ae22-4b55-8494-283156626879	t
91aad599-7aff-45b3-949c-21ce3d763581	1409bcea-a67b-4799-94b2-2543b59c9d45	t
91aad599-7aff-45b3-949c-21ce3d763581	81b5be5e-373c-47e0-ace8-299254218d88	t
91aad599-7aff-45b3-949c-21ce3d763581	78fefb8f-ad2c-4087-bf86-1ac5db378034	f
91aad599-7aff-45b3-949c-21ce3d763581	99895a6e-497a-46cd-8b5d-a9a26344509f	f
91aad599-7aff-45b3-949c-21ce3d763581	c25b82c3-20a8-45fb-976e-8160fb5a79b8	f
91aad599-7aff-45b3-949c-21ce3d763581	112556c8-d6c3-4620-a381-691d965c8165	f
e865f20a-8b9f-49dd-84e3-f2b6b4468a55	8580c6c6-4118-4bc8-8935-777a64d9de99	t
e865f20a-8b9f-49dd-84e3-f2b6b4468a55	920add0f-ae22-4b55-8494-283156626879	t
e865f20a-8b9f-49dd-84e3-f2b6b4468a55	1409bcea-a67b-4799-94b2-2543b59c9d45	t
e865f20a-8b9f-49dd-84e3-f2b6b4468a55	81b5be5e-373c-47e0-ace8-299254218d88	t
e865f20a-8b9f-49dd-84e3-f2b6b4468a55	78fefb8f-ad2c-4087-bf86-1ac5db378034	f
e865f20a-8b9f-49dd-84e3-f2b6b4468a55	99895a6e-497a-46cd-8b5d-a9a26344509f	f
e865f20a-8b9f-49dd-84e3-f2b6b4468a55	c25b82c3-20a8-45fb-976e-8160fb5a79b8	f
e865f20a-8b9f-49dd-84e3-f2b6b4468a55	112556c8-d6c3-4620-a381-691d965c8165	f
31531d43-30cf-4f40-8b04-2151b613e54a	8580c6c6-4118-4bc8-8935-777a64d9de99	t
31531d43-30cf-4f40-8b04-2151b613e54a	920add0f-ae22-4b55-8494-283156626879	t
31531d43-30cf-4f40-8b04-2151b613e54a	1409bcea-a67b-4799-94b2-2543b59c9d45	t
31531d43-30cf-4f40-8b04-2151b613e54a	81b5be5e-373c-47e0-ace8-299254218d88	t
31531d43-30cf-4f40-8b04-2151b613e54a	78fefb8f-ad2c-4087-bf86-1ac5db378034	f
31531d43-30cf-4f40-8b04-2151b613e54a	99895a6e-497a-46cd-8b5d-a9a26344509f	f
31531d43-30cf-4f40-8b04-2151b613e54a	c25b82c3-20a8-45fb-976e-8160fb5a79b8	f
31531d43-30cf-4f40-8b04-2151b613e54a	112556c8-d6c3-4620-a381-691d965c8165	f
7e747e82-a68b-46a8-a952-11e2b6f34a1b	8580c6c6-4118-4bc8-8935-777a64d9de99	t
7e747e82-a68b-46a8-a952-11e2b6f34a1b	920add0f-ae22-4b55-8494-283156626879	t
7e747e82-a68b-46a8-a952-11e2b6f34a1b	1409bcea-a67b-4799-94b2-2543b59c9d45	t
7e747e82-a68b-46a8-a952-11e2b6f34a1b	81b5be5e-373c-47e0-ace8-299254218d88	t
7e747e82-a68b-46a8-a952-11e2b6f34a1b	78fefb8f-ad2c-4087-bf86-1ac5db378034	f
7e747e82-a68b-46a8-a952-11e2b6f34a1b	99895a6e-497a-46cd-8b5d-a9a26344509f	f
7e747e82-a68b-46a8-a952-11e2b6f34a1b	c25b82c3-20a8-45fb-976e-8160fb5a79b8	f
7e747e82-a68b-46a8-a952-11e2b6f34a1b	112556c8-d6c3-4620-a381-691d965c8165	f
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	f806fc10-7e18-4823-8c40-e610cc7b3f52	t
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	8580c6c6-4118-4bc8-8935-777a64d9de99	t
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	920add0f-ae22-4b55-8494-283156626879	t
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	1409bcea-a67b-4799-94b2-2543b59c9d45	t
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	81b5be5e-373c-47e0-ace8-299254218d88	t
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	78fefb8f-ad2c-4087-bf86-1ac5db378034	f
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	99895a6e-497a-46cd-8b5d-a9a26344509f	f
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	c25b82c3-20a8-45fb-976e-8160fb5a79b8	f
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	112556c8-d6c3-4620-a381-691d965c8165	f
\.


--
-- Data for Name: client_scope_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_scope_role_mapping (scope_id, role_id) FROM stdin;
78fefb8f-ad2c-4087-bf86-1ac5db378034	b7b345a1-94a2-45ba-ad53-43b02bde60ae
\.


--
-- Data for Name: client_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session (id, client_id, redirect_uri, state, "timestamp", session_id, auth_method, realm_id, auth_user_id, current_action) FROM stdin;
\.


--
-- Data for Name: client_session_auth_status; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_auth_status (authenticator, status, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_note; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_note (name, value, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_prot_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_prot_mapper (protocol_mapper_id, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_role; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_session_role (role_id, client_session) FROM stdin;
\.


--
-- Data for Name: client_user_session_note; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.client_user_session_note (name, value, client_session) FROM stdin;
\.


--
-- Data for Name: component; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.component (id, name, parent_id, provider_id, provider_type, realm_id, sub_type) FROM stdin;
e092c6f3-8dba-41b1-9426-12319fe50088	Trusted Hosts	master	trusted-hosts	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
f6600d57-fb45-4535-8d0a-3367edd4af33	Consent Required	master	consent-required	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
85c7ebba-b45b-4432-b4dd-c58c0056bb52	Full Scope Disabled	master	scope	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
866eaa13-7e5f-43d4-b519-c09627bf3584	Max Clients Limit	master	max-clients	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
39f3cc37-dfd2-45da-905f-82f120801626	Allowed Protocol Mapper Types	master	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
b61e8636-f1b6-4491-bcbc-708ed071ee7f	Allowed Client Scopes	master	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
6d7f496b-8c53-4c10-a5fe-cd7169453998	Allowed Protocol Mapper Types	master	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	authenticated
44ef715c-f3f2-4d1e-97e8-8381710ae969	Allowed Client Scopes	master	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	authenticated
4eee0677-6bdd-4767-bfe5-7a2e896e639f	rsa-generated	master	rsa-generated	org.keycloak.keys.KeyProvider	master	\N
255ea1ce-2135-44b8-8548-96d403d0cf42	hmac-generated	master	hmac-generated	org.keycloak.keys.KeyProvider	master	\N
9e9156d4-b92a-4f19-8029-dcb4259a2645	aes-generated	master	aes-generated	org.keycloak.keys.KeyProvider	master	\N
\.


--
-- Data for Name: component_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.component_config (id, component_id, name, value) FROM stdin;
ed866bcb-f2aa-4cee-b590-f84b1501cd85	39f3cc37-dfd2-45da-905f-82f120801626	allowed-protocol-mapper-types	saml-user-attribute-mapper
7708ca05-1571-4d24-9bca-e48184e2f5d2	39f3cc37-dfd2-45da-905f-82f120801626	allowed-protocol-mapper-types	oidc-full-name-mapper
dffb4c85-47a1-4423-9acd-030faebe8ba9	39f3cc37-dfd2-45da-905f-82f120801626	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
de3a6126-ea7d-4fce-8817-b64b7dcc643e	39f3cc37-dfd2-45da-905f-82f120801626	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
2b9656ab-c182-402d-8ddb-52e804a870e1	39f3cc37-dfd2-45da-905f-82f120801626	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
111acb80-4e18-4e7a-8382-104f93c48f76	39f3cc37-dfd2-45da-905f-82f120801626	allowed-protocol-mapper-types	saml-role-list-mapper
c797d1f0-3229-4aff-bff9-26ee34c00695	39f3cc37-dfd2-45da-905f-82f120801626	allowed-protocol-mapper-types	oidc-address-mapper
fea822d0-24de-4e6c-bb9b-00065bc6316d	39f3cc37-dfd2-45da-905f-82f120801626	allowed-protocol-mapper-types	saml-user-property-mapper
6ee1709b-c465-47c8-9879-0b1cfad85e46	b61e8636-f1b6-4491-bcbc-708ed071ee7f	allow-default-scopes	true
934c4184-9477-4b24-a7cb-23fe58001c95	e092c6f3-8dba-41b1-9426-12319fe50088	client-uris-must-match	true
7eef976b-9cd0-4e9c-b33f-140e899352cf	e092c6f3-8dba-41b1-9426-12319fe50088	host-sending-registration-request-must-match	true
758346c2-1b6b-4a62-87e6-d03189fea8aa	866eaa13-7e5f-43d4-b519-c09627bf3584	max-clients	200
a5a93e03-66df-4a50-a49d-0ef9802a7ad4	44ef715c-f3f2-4d1e-97e8-8381710ae969	allow-default-scopes	true
1bb81faa-4def-4d28-b3e3-68975fde738f	6d7f496b-8c53-4c10-a5fe-cd7169453998	allowed-protocol-mapper-types	oidc-full-name-mapper
7458a419-d622-4fea-a6b8-a114535e3b83	6d7f496b-8c53-4c10-a5fe-cd7169453998	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
88c35eee-0eb7-4fe8-bf55-4d0229182bdb	6d7f496b-8c53-4c10-a5fe-cd7169453998	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
1751f451-a7b0-4f6a-9863-682c7b9f5b64	6d7f496b-8c53-4c10-a5fe-cd7169453998	allowed-protocol-mapper-types	saml-user-attribute-mapper
f57800f8-6675-464a-8b31-1a951ebdc419	6d7f496b-8c53-4c10-a5fe-cd7169453998	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
a84fdc59-4868-43c2-ae1d-20968e8894ef	6d7f496b-8c53-4c10-a5fe-cd7169453998	allowed-protocol-mapper-types	oidc-address-mapper
d54dd3dd-bcd9-4155-ab6f-ebf5b57dda32	6d7f496b-8c53-4c10-a5fe-cd7169453998	allowed-protocol-mapper-types	saml-role-list-mapper
b32fb21e-f201-483d-b531-9ad5370de6b8	6d7f496b-8c53-4c10-a5fe-cd7169453998	allowed-protocol-mapper-types	saml-user-property-mapper
a94261c2-97c6-4a7a-8b56-4cf7f2ca80d7	255ea1ce-2135-44b8-8548-96d403d0cf42	kid	ace0ec0d-8843-4d4b-aa5c-0e24da230f74
220e00a5-f80d-42d4-9984-6e641a52d7ad	255ea1ce-2135-44b8-8548-96d403d0cf42	secret	bY0NDg8tsNWVQfMT0WhTFsFwLsikiMkQneL79pXbvy6GK_zmdE5A9tVKdhJ-Zk3OEuLslMyn476sJx1j3HBwZA
e66b07da-4ef4-4bb2-b2a6-fcce940167b0	255ea1ce-2135-44b8-8548-96d403d0cf42	algorithm	HS256
c00a6985-c9ed-4df5-889c-f571639c3f9e	255ea1ce-2135-44b8-8548-96d403d0cf42	priority	100
33888ccd-38f2-44e5-b907-2cd404591042	4eee0677-6bdd-4767-bfe5-7a2e896e639f	certificate	MIICmzCCAYMCBgFtBoYEnTANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMTkwOTA2MTIyMDA5WhcNMjkwOTA2MTIyMTQ5WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCDk2YEDXN7MTQxlPBfMIjmRM0EaVjVkCRZRJUIgecXUFadXTETdG5UpM2OWcGnLMR3cRHO8PhDOpuuCnt6Np0fmRJq6Ys8e5dLehPNCoyBVPQB9HFCTZkm638n55IQYoWGntnF59qRQ3zQydwJsBTMhsS/7YIIot20X3gie862osugnp3SWEoXNlq3yYLacSOOVaeNxc9P/K6HbqzKQ4ghadu9D1/vdL5VPCnRNriv+Bfv46qqGx2RCTCgYGri+NjCJW1MSl+whIMif1hGHCdJD2M64MjcEeEANgIQ8aoidQ+N7NYIx5jAQy7FGq4FRWT6erhJZFphQiRXX/hREftTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAARu+ZFqrwjvA9z1NZQdEj9MrOtbpsc8Q6tNZLeA0QEwwFeVLTgMoYRO5GrTWkCoI/m34XfEqZA6CbhvlX9Or8HJIJuYOzXd/U3gexMhjT2RzmBrjTwoZ+UUxttYF3wzI5rJ0WIpIVjo+3/uXSaGqrU8s9FVOqvi8AFt4HGTKD0OSAS767nNOfHph7PMJuD3lfxwsPm7COG4VDeIP6H1kzrH9mvWkkFefQW1Vn8FvGnFu30N8XC1mnCvh4Um2xlBNFC0gX5F+eS+AUHPPadKiJ5exXUECMu3Ds8j8Y3JB/aez86pcCH/O6HU+2Iy1BD1BwvESs9eFJPnk7OPOM9WoWI=
31d6b930-6130-48b6-a9a0-ca4f2eb0f782	4eee0677-6bdd-4767-bfe5-7a2e896e639f	privateKey	MIIEowIBAAKCAQEAg5NmBA1zezE0MZTwXzCI5kTNBGlY1ZAkWUSVCIHnF1BWnV0xE3RuVKTNjlnBpyzEd3ERzvD4Qzqbrgp7ejadH5kSaumLPHuXS3oTzQqMgVT0AfRxQk2ZJut/J+eSEGKFhp7ZxefakUN80MncCbAUzIbEv+2CCKLdtF94InvOtqLLoJ6d0lhKFzZat8mC2nEjjlWnjcXPT/yuh26sykOIIWnbvQ9f73S+VTwp0Ta4r/gX7+OqqhsdkQkwoGBq4vjYwiVtTEpfsISDIn9YRhwnSQ9jOuDI3BHhADYCEPGqInUPjezWCMeYwEMuxRquBUVk+nq4SWRaYUIkV1/4URH7UwIDAQABAoIBAGyEkUseXPRp7IZINMgNm5tvezf8OwxIyfHmIpTVrucHl6hKSEOnb6fYFMEnPhTHU3K/itSG4ftwxx2P/68YhBafhRUwcWn89ReHI/WkkaXJj0ZdeVwZ7AqxiDo9P7bLyxzwvuP/CcFtS/BXzGchFsZpELTLCshcq0Ysx0SJoD/4awc9Rmy6meaL0P8+oe6hoGH81ly5PHO/fDk8bU+3A66AUqpc9BvP0ui4cKeJBL0LAlrJoEn9jAr2qSvHGYSU3ZR3TX2jCJI53dq6daySpaJp4gpuY6RhlQ4GyDmMYRqYDJbBJjqsLTHez+IfeOZVRZrTQbjY6jdZ7E5Qq+3nUsECgYEA0zDk0PVXHLx7ka/ItMXBuYFxEeG2m4OJSJVFQmLF/cddLcY6ASPCnYZ304/RA0jORKVXg901cmPAQRbMUJDt8RoUgbSG0ZOZbaeGnApKqQdBVFZVSDbrcfa4ut0yOlS/XzHCcZaySLQ5Vba65l6VYQ8TafH8Dd4Xn8xKiO1L3jkCgYEAn34ad58bepsFFrCrdBZflfwosHPaMH9iSpFBpx8VBnhq+xgotyGcRaI2SG0Juw7EvTslP4tDkWjfR8U3GNgkF1WFD6Pi0okLD+0+o6+WhtpZnyybzdnF0+tn6rGJsmsFbly+oVDcnJyku0og+5bIXAzHsbS8TeAITiIH11PE5esCgYEAu1uME6kkYDUCtyuotl8ez1D7m66PzwVxnHf42r1AAzWD/6D1Qp+T/yYVVhYnim9jttisfCqaSOIf5F6yYeNBhHzrpmoelP0Jx5Mww2wJ8kyic4yn2goG9LK6DeVAsykOIgjGBPl5LzDcEKOsycUtZs72HS51u2PFt5mIolNK1FkCgYBhv8Gs6sDGpde6jlCmd0fh/odZjcd9zbSKCvh32p7iNk8q0SWzB1BlhQNL5DgAgw6lA2jSxyGELwgZTo90FJQaEPnaGhFcA03aVwb6/xR8Vbpzyb07rmqGdVJdDq5bwSe0+faDm7F58q8rckVArKrjb5m8Gg8Gk3XDnSu9FsQoPQKBgGsEQ6Pp4KbscoLscv1JBijjIW31rc10NX3z20VREHhVR0dfCip/aW77U+a7Zbst5trme4gUvz0Yd8hTQZXwt6iLqO65A2q8SicNGwghZM9C6+0Fp82hVeVzEZEGJj7/dGPLVBqCo9bejiodQbbqkRjXMw3HBQtca22eAbfMckVv
736e9b22-b031-4908-aa69-40e9d557dd31	4eee0677-6bdd-4767-bfe5-7a2e896e639f	priority	100
c5f21c47-f436-461f-91e0-94eb1055bbc7	9e9156d4-b92a-4f19-8029-dcb4259a2645	priority	100
8b868952-04dd-410a-9c64-c18250af4da0	9e9156d4-b92a-4f19-8029-dcb4259a2645	secret	o1pItfq_SMVRydCAXjnFcg
09884f48-f4fa-4d19-8430-38d70ac87c54	9e9156d4-b92a-4f19-8029-dcb4259a2645	kid	dd6a037a-e7b0-45e9-9cd3-a8f29a94570e
\.


--
-- Data for Name: composite_role; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.composite_role (composite, child_role) FROM stdin;
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	54ddec8f-b060-46bc-a2ed-ac0febc015fd
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	8968e575-fbfc-495f-abf0-fc690584510c
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	953e9dfe-c1d7-47a3-ac9b-428e9eb031ff
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	e5709e10-4cd5-46ab-bf52-ad76c9dd11bc
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	df516962-0e90-4416-80f8-a3dd64c6f84b
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	66f70108-6a36-42e2-9ab3-17bd1940aadd
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	76162eed-8a57-4b4c-8fa4-9ab0b5e68f79
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	69adff5f-ea30-4e2b-bd77-6e1991147d43
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	2175e97b-39e5-49dd-b0de-0aa965f4478d
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	36b61e09-d98c-4662-b5c2-24088a6aa569
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	5d46775b-74ee-4c36-ac1d-21d1b44560bd
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	d19415a2-50c5-4a6a-a06e-3c6727e568cb
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	44364e8f-999a-4fb6-a901-57e4fbeaedd9
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	a38145d5-8154-4355-a5be-a230dbae260f
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	bea96b59-bad7-4644-96ad-0efb245f0198
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	d9b67edb-15d5-4cb0-a0bc-b5ddd85d8eb4
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	ea59b58a-300b-4ac1-be19-bfaef865fcaf
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	75d4ed15-5528-4745-a95c-487d5532991b
e5709e10-4cd5-46ab-bf52-ad76c9dd11bc	bea96b59-bad7-4644-96ad-0efb245f0198
e5709e10-4cd5-46ab-bf52-ad76c9dd11bc	75d4ed15-5528-4745-a95c-487d5532991b
df516962-0e90-4416-80f8-a3dd64c6f84b	d9b67edb-15d5-4cb0-a0bc-b5ddd85d8eb4
43a803f1-931f-4c65-98b6-d741c5c00170	683efa2a-5c8e-4f8e-a3ba-f8c95a50cd8a
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	69124c8f-18d5-4c73-9e6c-e62233b2e619
\.


--
-- Data for Name: credential; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.credential (id, device, hash_iterations, salt, type, value, user_id, created_date, counter, digits, period, algorithm) FROM stdin;
28b489c2-a773-4e82-846e-f3412e34284a	\N	27500	\\xad0da824d9802577bea1bbbe015737ec	password	Cx2OCD5EkCtItfyacjctH+fF2WoWh6BN8wOHoQgZet4cIelOPbsrXwESG5FUpkVLt9MC1DRTXSNtROWp0liKTg==	4c16dcbf-12d8-40d3-8879-a24882e11f06	\N	0	0	0	pbkdf2-sha256
0ace4c90-d004-4b1b-9697-76c74de9e410	\N	27500	\\xf0da128a3b417ee6b340f1ed4066aa46	password	BhnCm7oDddDOoAQ3/bxsxEBHTW7CeTBhvguhKsQZE4PAByhmbJ8WKkMcbLiznzkB6jhxIML0ayxb5AVg7FwyMA==	64c0212e-85bd-4eda-90d9-a5fc22eafb68	1568027453694	0	0	0	pbkdf2-sha256
\.


--
-- Data for Name: credential_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.credential_attribute (id, credential_id, name, value) FROM stdin;
\.


--
-- Data for Name: databasechangelog; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, md5sum, description, comments, tag, liquibase, contexts, labels, deployment_id) FROM stdin;
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/jpa-changelog-1.0.0.Final.xml	2019-09-06 12:21:42.185379	1	EXECUTED	7:4e70412f24a3f382c82183742ec79317	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	3.5.4	\N	\N	7772501758
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/db2-jpa-changelog-1.0.0.Final.xml	2019-09-06 12:21:42.215159	2	MARK_RAN	7:cb16724583e9675711801c6875114f28	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	3.5.4	\N	\N	7772501758
1.1.0.Beta1	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Beta1.xml	2019-09-06 12:21:42.27286	3	EXECUTED	7:0310eb8ba07cec616460794d42ade0fa	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=CLIENT_ATTRIBUTES; createTable tableName=CLIENT_SESSION_NOTE; createTable tableName=APP_NODE_REGISTRATIONS; addColumn table...		\N	3.5.4	\N	\N	7772501758
1.1.0.Final	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Final.xml	2019-09-06 12:21:42.278199	4	EXECUTED	7:5d25857e708c3233ef4439df1f93f012	renameColumn newColumnName=EVENT_TIME, oldColumnName=TIME, tableName=EVENT_ENTITY		\N	3.5.4	\N	\N	7772501758
1.2.0.Beta1	psilva@redhat.com	META-INF/jpa-changelog-1.2.0.Beta1.xml	2019-09-06 12:21:42.40757	5	EXECUTED	7:c7a54a1041d58eb3817a4a883b4d4e84	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	3.5.4	\N	\N	7772501758
1.2.0.Beta1	psilva@redhat.com	META-INF/db2-jpa-changelog-1.2.0.Beta1.xml	2019-09-06 12:21:42.413242	6	MARK_RAN	7:2e01012df20974c1c2a605ef8afe25b7	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	3.5.4	\N	\N	7772501758
1.2.0.RC1	bburke@redhat.com	META-INF/jpa-changelog-1.2.0.CR1.xml	2019-09-06 12:21:42.529894	7	EXECUTED	7:0f08df48468428e0f30ee59a8ec01a41	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	3.5.4	\N	\N	7772501758
1.2.0.RC1	bburke@redhat.com	META-INF/db2-jpa-changelog-1.2.0.CR1.xml	2019-09-06 12:21:42.537429	8	MARK_RAN	7:a77ea2ad226b345e7d689d366f185c8c	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	3.5.4	\N	\N	7772501758
1.2.0.Final	keycloak	META-INF/jpa-changelog-1.2.0.Final.xml	2019-09-06 12:21:42.544406	9	EXECUTED	7:a3377a2059aefbf3b90ebb4c4cc8e2ab	update tableName=CLIENT; update tableName=CLIENT; update tableName=CLIENT		\N	3.5.4	\N	\N	7772501758
1.3.0	bburke@redhat.com	META-INF/jpa-changelog-1.3.0.xml	2019-09-06 12:21:42.679769	10	EXECUTED	7:04c1dbedc2aa3e9756d1a1668e003451	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=ADMI...		\N	3.5.4	\N	\N	7772501758
1.4.0	bburke@redhat.com	META-INF/jpa-changelog-1.4.0.xml	2019-09-06 12:21:42.77416	11	EXECUTED	7:36ef39ed560ad07062d956db861042ba	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	7772501758
1.4.0	bburke@redhat.com	META-INF/db2-jpa-changelog-1.4.0.xml	2019-09-06 12:21:42.7781	12	MARK_RAN	7:d909180b2530479a716d3f9c9eaea3d7	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	7772501758
1.5.0	bburke@redhat.com	META-INF/jpa-changelog-1.5.0.xml	2019-09-06 12:21:42.880073	13	EXECUTED	7:cf12b04b79bea5152f165eb41f3955f6	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	7772501758
1.6.1_from15	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 12:21:42.925525	14	EXECUTED	7:7e32c8f05c755e8675764e7d5f514509	addColumn tableName=REALM; addColumn tableName=KEYCLOAK_ROLE; addColumn tableName=CLIENT; createTable tableName=OFFLINE_USER_SESSION; createTable tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_US_SES_PK2, tableName=...		\N	3.5.4	\N	\N	7772501758
1.6.1_from16-pre	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 12:21:42.92796	15	MARK_RAN	7:980ba23cc0ec39cab731ce903dd01291	delete tableName=OFFLINE_CLIENT_SESSION; delete tableName=OFFLINE_USER_SESSION		\N	3.5.4	\N	\N	7772501758
1.6.1_from16	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 12:21:42.930301	16	MARK_RAN	7:2fa220758991285312eb84f3b4ff5336	dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_US_SES_PK, tableName=OFFLINE_USER_SESSION; dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_CL_SES_PK, tableName=OFFLINE_CLIENT_SESSION; addColumn tableName=OFFLINE_USER_SESSION; update tableName=OF...		\N	3.5.4	\N	\N	7772501758
1.6.1	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2019-09-06 12:21:42.932754	17	EXECUTED	7:d41d8cd98f00b204e9800998ecf8427e	empty		\N	3.5.4	\N	\N	7772501758
1.7.0	bburke@redhat.com	META-INF/jpa-changelog-1.7.0.xml	2019-09-06 12:21:43.017582	18	EXECUTED	7:91ace540896df890cc00a0490ee52bbc	createTable tableName=KEYCLOAK_GROUP; createTable tableName=GROUP_ROLE_MAPPING; createTable tableName=GROUP_ATTRIBUTE; createTable tableName=USER_GROUP_MEMBERSHIP; createTable tableName=REALM_DEFAULT_GROUPS; addColumn tableName=IDENTITY_PROVIDER; ...		\N	3.5.4	\N	\N	7772501758
1.8.0	mposolda@redhat.com	META-INF/jpa-changelog-1.8.0.xml	2019-09-06 12:21:43.091406	19	EXECUTED	7:c31d1646dfa2618a9335c00e07f89f24	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	3.5.4	\N	\N	7772501758
1.8.0-2	keycloak	META-INF/jpa-changelog-1.8.0.xml	2019-09-06 12:21:43.100156	20	EXECUTED	7:df8bc21027a4f7cbbb01f6344e89ce07	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	3.5.4	\N	\N	7772501758
authz-3.4.0.CR1-resource-server-pk-change-part1	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 12:21:43.74483	45	EXECUTED	7:6a48ce645a3525488a90fbf76adf3bb3	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_RESOURCE; addColumn tableName=RESOURCE_SERVER_SCOPE		\N	3.5.4	\N	\N	7772501758
1.8.0	mposolda@redhat.com	META-INF/db2-jpa-changelog-1.8.0.xml	2019-09-06 12:21:43.102581	21	MARK_RAN	7:f987971fe6b37d963bc95fee2b27f8df	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	3.5.4	\N	\N	7772501758
1.8.0-2	keycloak	META-INF/db2-jpa-changelog-1.8.0.xml	2019-09-06 12:21:43.105426	22	MARK_RAN	7:df8bc21027a4f7cbbb01f6344e89ce07	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	3.5.4	\N	\N	7772501758
1.9.0	mposolda@redhat.com	META-INF/jpa-changelog-1.9.0.xml	2019-09-06 12:21:43.125418	23	EXECUTED	7:ed2dc7f799d19ac452cbcda56c929e47	update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=REALM; update tableName=REALM; customChange; dr...		\N	3.5.4	\N	\N	7772501758
1.9.1	keycloak	META-INF/jpa-changelog-1.9.1.xml	2019-09-06 12:21:43.130854	24	EXECUTED	7:80b5db88a5dda36ece5f235be8757615	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=PUBLIC_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	3.5.4	\N	\N	7772501758
1.9.1	keycloak	META-INF/db2-jpa-changelog-1.9.1.xml	2019-09-06 12:21:43.133554	25	MARK_RAN	7:1437310ed1305a9b93f8848f301726ce	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	3.5.4	\N	\N	7772501758
1.9.2	keycloak	META-INF/jpa-changelog-1.9.2.xml	2019-09-06 12:21:43.163305	26	EXECUTED	7:b82ffb34850fa0836be16deefc6a87c4	createIndex indexName=IDX_USER_EMAIL, tableName=USER_ENTITY; createIndex indexName=IDX_USER_ROLE_MAPPING, tableName=USER_ROLE_MAPPING; createIndex indexName=IDX_USER_GROUP_MAPPING, tableName=USER_GROUP_MEMBERSHIP; createIndex indexName=IDX_USER_CO...		\N	3.5.4	\N	\N	7772501758
authz-2.0.0	psilva@redhat.com	META-INF/jpa-changelog-authz-2.0.0.xml	2019-09-06 12:21:43.289146	27	EXECUTED	7:9cc98082921330d8d9266decdd4bd658	createTable tableName=RESOURCE_SERVER; addPrimaryKey constraintName=CONSTRAINT_FARS, tableName=RESOURCE_SERVER; addUniqueConstraint constraintName=UK_AU8TT6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER; createTable tableName=RESOURCE_SERVER_RESOU...		\N	3.5.4	\N	\N	7772501758
authz-2.5.1	psilva@redhat.com	META-INF/jpa-changelog-authz-2.5.1.xml	2019-09-06 12:21:43.297186	28	EXECUTED	7:03d64aeed9cb52b969bd30a7ac0db57e	update tableName=RESOURCE_SERVER_POLICY		\N	3.5.4	\N	\N	7772501758
2.1.0-KEYCLOAK-5461	bburke@redhat.com	META-INF/jpa-changelog-2.1.0.xml	2019-09-06 12:21:43.401835	29	EXECUTED	7:f1f9fd8710399d725b780f463c6b21cd	createTable tableName=BROKER_LINK; createTable tableName=FED_USER_ATTRIBUTE; createTable tableName=FED_USER_CONSENT; createTable tableName=FED_USER_CONSENT_ROLE; createTable tableName=FED_USER_CONSENT_PROT_MAPPER; createTable tableName=FED_USER_CR...		\N	3.5.4	\N	\N	7772501758
2.2.0	bburke@redhat.com	META-INF/jpa-changelog-2.2.0.xml	2019-09-06 12:21:43.434037	30	EXECUTED	7:53188c3eb1107546e6f765835705b6c1	addColumn tableName=ADMIN_EVENT_ENTITY; createTable tableName=CREDENTIAL_ATTRIBUTE; createTable tableName=FED_CREDENTIAL_ATTRIBUTE; modifyDataType columnName=VALUE, tableName=CREDENTIAL; addForeignKeyConstraint baseTableName=FED_CREDENTIAL_ATTRIBU...		\N	3.5.4	\N	\N	7772501758
2.3.0	bburke@redhat.com	META-INF/jpa-changelog-2.3.0.xml	2019-09-06 12:21:43.457738	31	EXECUTED	7:d6e6f3bc57a0c5586737d1351725d4d4	createTable tableName=FEDERATED_USER; addPrimaryKey constraintName=CONSTR_FEDERATED_USER, tableName=FEDERATED_USER; dropDefaultValue columnName=TOTP, tableName=USER_ENTITY; dropColumn columnName=TOTP, tableName=USER_ENTITY; addColumn tableName=IDE...		\N	3.5.4	\N	\N	7772501758
2.4.0	bburke@redhat.com	META-INF/jpa-changelog-2.4.0.xml	2019-09-06 12:21:43.46434	32	EXECUTED	7:454d604fbd755d9df3fd9c6329043aa5	customChange		\N	3.5.4	\N	\N	7772501758
2.5.0	bburke@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 12:21:43.472783	33	EXECUTED	7:57e98a3077e29caf562f7dbf80c72600	customChange; modifyDataType columnName=USER_ID, tableName=OFFLINE_USER_SESSION		\N	3.5.4	\N	\N	7772501758
2.5.0-unicode-oracle	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 12:21:43.475689	34	MARK_RAN	7:e4c7e8f2256210aee71ddc42f538b57a	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	3.5.4	\N	\N	7772501758
2.5.0-unicode-other-dbs	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 12:21:43.506045	35	EXECUTED	7:09a43c97e49bc626460480aa1379b522	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	3.5.4	\N	\N	7772501758
2.5.0-duplicate-email-support	slawomir@dabek.name	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 12:21:43.527572	36	EXECUTED	7:26bfc7c74fefa9126f2ce702fb775553	addColumn tableName=REALM		\N	3.5.4	\N	\N	7772501758
2.5.0-unique-group-names	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2019-09-06 12:21:43.533151	37	EXECUTED	7:a161e2ae671a9020fff61e996a207377	addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	3.5.4	\N	\N	7772501758
2.5.1	bburke@redhat.com	META-INF/jpa-changelog-2.5.1.xml	2019-09-06 12:21:43.537091	38	EXECUTED	7:37fc1781855ac5388c494f1442b3f717	addColumn tableName=FED_USER_CONSENT		\N	3.5.4	\N	\N	7772501758
3.0.0	bburke@redhat.com	META-INF/jpa-changelog-3.0.0.xml	2019-09-06 12:21:43.548112	39	EXECUTED	7:13a27db0dae6049541136adad7261d27	addColumn tableName=IDENTITY_PROVIDER		\N	3.5.4	\N	\N	7772501758
3.2.0-fix	keycloak	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 12:21:43.550405	40	MARK_RAN	7:550300617e3b59e8af3a6294df8248a3	addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS		\N	3.5.4	\N	\N	7772501758
3.2.0-fix-with-keycloak-5416	keycloak	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 12:21:43.552278	41	MARK_RAN	7:e3a9482b8931481dc2772a5c07c44f17	dropIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS; addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS; createIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS		\N	3.5.4	\N	\N	7772501758
3.2.0-fix-offline-sessions	hmlnarik	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 12:21:43.557068	42	EXECUTED	7:72b07d85a2677cb257edb02b408f332d	customChange		\N	3.5.4	\N	\N	7772501758
3.2.0-fixed	keycloak	META-INF/jpa-changelog-3.2.0.xml	2019-09-06 12:21:43.710125	43	EXECUTED	7:a72a7858967bd414835d19e04d880312	addColumn tableName=REALM; dropPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_PK2, tableName=OFFLINE_CLIENT_SESSION; dropColumn columnName=CLIENT_SESSION_ID, tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_P...		\N	3.5.4	\N	\N	7772501758
3.3.0	keycloak	META-INF/jpa-changelog-3.3.0.xml	2019-09-06 12:21:43.736114	44	EXECUTED	7:94edff7cf9ce179e7e85f0cd78a3cf2c	addColumn tableName=USER_ENTITY		\N	3.5.4	\N	\N	7772501758
authz-3.4.0.CR1-resource-server-pk-change-part2-KEYCLOAK-6095	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 12:21:43.753976	46	EXECUTED	7:e64b5dcea7db06077c6e57d3b9e5ca14	customChange		\N	3.5.4	\N	\N	7772501758
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 12:21:43.757387	47	MARK_RAN	7:fd8cf02498f8b1e72496a20afc75178c	dropIndex indexName=IDX_RES_SERV_POL_RES_SERV, tableName=RESOURCE_SERVER_POLICY; dropIndex indexName=IDX_RES_SRV_RES_RES_SRV, tableName=RESOURCE_SERVER_RESOURCE; dropIndex indexName=IDX_RES_SRV_SCOPE_RES_SRV, tableName=RESOURCE_SERVER_SCOPE		\N	3.5.4	\N	\N	7772501758
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed-nodropindex	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 12:21:43.818518	48	EXECUTED	7:542794f25aa2b1fbabb7e577d6646319	addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_POLICY; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_RESOURCE; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, ...		\N	3.5.4	\N	\N	7772501758
authn-3.4.0.CR1-refresh-token-max-reuse	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2019-09-06 12:21:43.845184	49	EXECUTED	7:edad604c882df12f74941dac3cc6d650	addColumn tableName=REALM		\N	3.5.4	\N	\N	7772501758
3.4.0	keycloak	META-INF/jpa-changelog-3.4.0.xml	2019-09-06 12:21:43.901505	50	EXECUTED	7:0f88b78b7b46480eb92690cbf5e44900	addPrimaryKey constraintName=CONSTRAINT_REALM_DEFAULT_ROLES, tableName=REALM_DEFAULT_ROLES; addPrimaryKey constraintName=CONSTRAINT_COMPOSITE_ROLE, tableName=COMPOSITE_ROLE; addPrimaryKey constraintName=CONSTR_REALM_DEFAULT_GROUPS, tableName=REALM...		\N	3.5.4	\N	\N	7772501758
3.4.0-KEYCLOAK-5230	hmlnarik@redhat.com	META-INF/jpa-changelog-3.4.0.xml	2019-09-06 12:21:43.932288	51	EXECUTED	7:d560e43982611d936457c327f872dd59	createIndex indexName=IDX_FU_ATTRIBUTE, tableName=FED_USER_ATTRIBUTE; createIndex indexName=IDX_FU_CONSENT, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CONSENT_RU, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CREDENTIAL, t...		\N	3.5.4	\N	\N	7772501758
3.4.1	psilva@redhat.com	META-INF/jpa-changelog-3.4.1.xml	2019-09-06 12:21:43.93558	52	EXECUTED	7:c155566c42b4d14ef07059ec3b3bbd8e	modifyDataType columnName=VALUE, tableName=CLIENT_ATTRIBUTES		\N	3.5.4	\N	\N	7772501758
3.4.2	keycloak	META-INF/jpa-changelog-3.4.2.xml	2019-09-06 12:21:43.938512	53	EXECUTED	7:b40376581f12d70f3c89ba8ddf5b7dea	update tableName=REALM		\N	3.5.4	\N	\N	7772501758
3.4.2-KEYCLOAK-5172	mkanis@redhat.com	META-INF/jpa-changelog-3.4.2.xml	2019-09-06 12:21:43.941259	54	EXECUTED	7:a1132cc395f7b95b3646146c2e38f168	update tableName=CLIENT		\N	3.5.4	\N	\N	7772501758
4.0.0-KEYCLOAK-6335	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 12:21:43.948101	55	EXECUTED	7:d8dc5d89c789105cfa7ca0e82cba60af	createTable tableName=CLIENT_AUTH_FLOW_BINDINGS; addPrimaryKey constraintName=C_CLI_FLOW_BIND, tableName=CLIENT_AUTH_FLOW_BINDINGS		\N	3.5.4	\N	\N	7772501758
4.0.0-CLEANUP-UNUSED-TABLE	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 12:21:43.95267	56	EXECUTED	7:7822e0165097182e8f653c35517656a3	dropTable tableName=CLIENT_IDENTITY_PROV_MAPPING		\N	3.5.4	\N	\N	7772501758
4.0.0-KEYCLOAK-6228	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 12:21:43.982369	57	EXECUTED	7:c6538c29b9c9a08f9e9ea2de5c2b6375	dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; dropNotNullConstraint columnName=CLIENT_ID, tableName=USER_CONSENT; addColumn tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHO...		\N	3.5.4	\N	\N	7772501758
4.0.0-KEYCLOAK-5579-fixed	mposolda@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2019-09-06 12:21:44.058378	58	EXECUTED	7:6d4893e36de22369cf73bcb051ded875	dropForeignKeyConstraint baseTableName=CLIENT_TEMPLATE_ATTRIBUTES, constraintName=FK_CL_TEMPL_ATTR_TEMPL; renameTable newTableName=CLIENT_SCOPE_ATTRIBUTES, oldTableName=CLIENT_TEMPLATE_ATTRIBUTES; renameColumn newColumnName=SCOPE_ID, oldColumnName...		\N	3.5.4	\N	\N	7772501758
authz-4.0.0.CR1	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.CR1.xml	2019-09-06 12:21:44.099393	59	EXECUTED	7:57960fc0b0f0dd0563ea6f8b2e4a1707	createTable tableName=RESOURCE_SERVER_PERM_TICKET; addPrimaryKey constraintName=CONSTRAINT_FAPMT, tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRHO213XCX4WNKOG82SSPMT...		\N	3.5.4	\N	\N	7772501758
authz-4.0.0.Beta3	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.Beta3.xml	2019-09-06 12:21:44.104349	60	EXECUTED	7:2b4b8bff39944c7097977cc18dbceb3b	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRPO2128CX4WNKOG82SSRFY, referencedTableName=RESOURCE_SERVER_POLICY		\N	3.5.4	\N	\N	7772501758
authz-4.2.0.Final	mhajas@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2019-09-06 12:21:44.112592	61	EXECUTED	7:2aa42a964c59cd5b8ca9822340ba33a8	createTable tableName=RESOURCE_URIS; addForeignKeyConstraint baseTableName=RESOURCE_URIS, constraintName=FK_RESOURCE_SERVER_URIS, referencedTableName=RESOURCE_SERVER_RESOURCE; customChange; dropColumn columnName=URI, tableName=RESOURCE_SERVER_RESO...		\N	3.5.4	\N	\N	7772501758
4.2.0-KEYCLOAK-6313	wadahiro@gmail.com	META-INF/jpa-changelog-4.2.0.xml	2019-09-06 12:21:44.116532	62	EXECUTED	7:14d407c35bc4fe1976867756bcea0c36	addColumn tableName=REQUIRED_ACTION_PROVIDER		\N	3.5.4	\N	\N	7772501758
4.3.0-KEYCLOAK-7984	wadahiro@gmail.com	META-INF/jpa-changelog-4.3.0.xml	2019-09-06 12:21:44.119314	63	EXECUTED	7:241a8030c748c8548e346adee548fa93	update tableName=REQUIRED_ACTION_PROVIDER		\N	3.5.4	\N	\N	7772501758
4.6.0-KEYCLOAK-7950	psilva@redhat.com	META-INF/jpa-changelog-4.6.0.xml	2019-09-06 12:21:44.121995	64	EXECUTED	7:7d3182f65a34fcc61e8d23def037dc3f	update tableName=RESOURCE_SERVER_RESOURCE		\N	3.5.4	\N	\N	7772501758
4.6.0-KEYCLOAK-8377	keycloak	META-INF/jpa-changelog-4.6.0.xml	2019-09-06 12:21:44.135006	65	EXECUTED	7:b30039e00a0b9715d430d1b0636728fa	createTable tableName=ROLE_ATTRIBUTE; addPrimaryKey constraintName=CONSTRAINT_ROLE_ATTRIBUTE_PK, tableName=ROLE_ATTRIBUTE; addForeignKeyConstraint baseTableName=ROLE_ATTRIBUTE, constraintName=FK_ROLE_ATTRIBUTE_ID, referencedTableName=KEYCLOAK_ROLE...		\N	3.5.4	\N	\N	7772501758
4.6.0-KEYCLOAK-8555	gideonray@gmail.com	META-INF/jpa-changelog-4.6.0.xml	2019-09-06 12:21:44.141624	66	EXECUTED	7:3797315ca61d531780f8e6f82f258159	createIndex indexName=IDX_COMPONENT_PROVIDER_TYPE, tableName=COMPONENT		\N	3.5.4	\N	\N	7772501758
4.7.0-KEYCLOAK-1267	sguilhen@redhat.com	META-INF/jpa-changelog-4.7.0.xml	2019-09-06 12:21:44.187261	67	EXECUTED	7:c7aa4c8d9573500c2d347c1941ff0301	addColumn tableName=REALM		\N	3.5.4	\N	\N	7772501758
4.7.0-KEYCLOAK-7275	keycloak	META-INF/jpa-changelog-4.7.0.xml	2019-09-06 12:21:44.209629	68	EXECUTED	7:b207faee394fc074a442ecd42185a5dd	renameColumn newColumnName=CREATED_ON, oldColumnName=LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION; addNotNullConstraint columnName=CREATED_ON, tableName=OFFLINE_USER_SESSION; addColumn tableName=OFFLINE_USER_SESSION; customChange; createIn...		\N	3.5.4	\N	\N	7772501758
4.8.0-KEYCLOAK-8835	sguilhen@redhat.com	META-INF/jpa-changelog-4.8.0.xml	2019-09-06 12:21:44.217728	69	EXECUTED	7:ab9a9762faaba4ddfa35514b212c4922	addNotNullConstraint columnName=SSO_MAX_LIFESPAN_REMEMBER_ME, tableName=REALM; addNotNullConstraint columnName=SSO_IDLE_TIMEOUT_REMEMBER_ME, tableName=REALM		\N	3.5.4	\N	\N	7772501758
\.


--
-- Data for Name: databasechangeloglock; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.databasechangeloglock (id, locked, lockgranted, lockedby) FROM stdin;
1	f	\N	\N
\.


--
-- Data for Name: default_client_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.default_client_scope (realm_id, scope_id, default_scope) FROM stdin;
master	78fefb8f-ad2c-4087-bf86-1ac5db378034	f
master	f806fc10-7e18-4823-8c40-e610cc7b3f52	t
master	8580c6c6-4118-4bc8-8935-777a64d9de99	t
master	920add0f-ae22-4b55-8494-283156626879	t
master	99895a6e-497a-46cd-8b5d-a9a26344509f	f
master	c25b82c3-20a8-45fb-976e-8160fb5a79b8	f
master	1409bcea-a67b-4799-94b2-2543b59c9d45	t
master	81b5be5e-373c-47e0-ace8-299254218d88	t
master	112556c8-d6c3-4620-a381-691d965c8165	f
\.


--
-- Data for Name: event_entity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.event_entity (id, client_id, details_json, error, ip_address, realm_id, session_id, event_time, type, user_id) FROM stdin;
\.


--
-- Data for Name: fed_credential_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_credential_attribute (id, credential_id, name, value) FROM stdin;
\.


--
-- Data for Name: fed_user_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_attribute (id, name, user_id, realm_id, storage_provider_id, value) FROM stdin;
\.


--
-- Data for Name: fed_user_consent; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_consent (id, client_id, user_id, realm_id, storage_provider_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: fed_user_consent_cl_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_consent_cl_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: fed_user_credential; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_credential (id, device, hash_iterations, salt, type, value, created_date, counter, digits, period, algorithm, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_group_membership; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_group_membership (group_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_required_action; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_required_action (required_action, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.fed_user_role_mapping (role_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: federated_identity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.federated_identity (identity_provider, realm_id, federated_user_id, federated_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: federated_user; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.federated_user (id, storage_provider_id, realm_id) FROM stdin;
\.


--
-- Data for Name: group_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.group_attribute (id, name, value, group_id) FROM stdin;
\.


--
-- Data for Name: group_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.group_role_mapping (role_id, group_id) FROM stdin;
\.


--
-- Data for Name: identity_provider; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.identity_provider (internal_id, enabled, provider_alias, provider_id, store_token, authenticate_by_default, realm_id, add_token_role, trust_email, first_broker_login_flow_id, post_broker_login_flow_id, provider_display_name, link_only) FROM stdin;
\.


--
-- Data for Name: identity_provider_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.identity_provider_config (identity_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: identity_provider_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.identity_provider_mapper (id, name, idp_alias, idp_mapper_name, realm_id) FROM stdin;
\.


--
-- Data for Name: idp_mapper_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.idp_mapper_config (idp_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: keycloak_group; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.keycloak_group (id, name, parent_group, realm_id) FROM stdin;
5b89a816-6556-4a76-8a4f-b2e42c541860	can-do-this-flaminem	\N	master
b46671c7-4bc5-43ce-802b-8146d0d14971	can-do-that-flaminem	\N	master
\.


--
-- Data for Name: keycloak_role; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.keycloak_role (id, client_realm_constraint, client_role, description, name, realm_id, client, realm) FROM stdin;
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	master	f	${role_admin}	admin	master	\N	master
54ddec8f-b060-46bc-a2ed-ac0febc015fd	master	f	${role_create-realm}	create-realm	master	\N	master
8968e575-fbfc-495f-abf0-fc690584510c	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_create-client}	create-client	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
953e9dfe-c1d7-47a3-ac9b-428e9eb031ff	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_view-realm}	view-realm	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
e5709e10-4cd5-46ab-bf52-ad76c9dd11bc	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_view-users}	view-users	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
df516962-0e90-4416-80f8-a3dd64c6f84b	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_view-clients}	view-clients	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
66f70108-6a36-42e2-9ab3-17bd1940aadd	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_view-events}	view-events	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
76162eed-8a57-4b4c-8fa4-9ab0b5e68f79	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_view-identity-providers}	view-identity-providers	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
69adff5f-ea30-4e2b-bd77-6e1991147d43	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_view-authorization}	view-authorization	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
2175e97b-39e5-49dd-b0de-0aa965f4478d	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_manage-realm}	manage-realm	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
36b61e09-d98c-4662-b5c2-24088a6aa569	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_manage-users}	manage-users	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
5d46775b-74ee-4c36-ac1d-21d1b44560bd	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_manage-clients}	manage-clients	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
d19415a2-50c5-4a6a-a06e-3c6727e568cb	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_manage-events}	manage-events	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
44364e8f-999a-4fb6-a901-57e4fbeaedd9	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_manage-identity-providers}	manage-identity-providers	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
a38145d5-8154-4355-a5be-a230dbae260f	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_manage-authorization}	manage-authorization	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
bea96b59-bad7-4644-96ad-0efb245f0198	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_query-users}	query-users	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
d9b67edb-15d5-4cb0-a0bc-b5ddd85d8eb4	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_query-clients}	query-clients	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
ea59b58a-300b-4ac1-be19-bfaef865fcaf	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_query-realms}	query-realms	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
75d4ed15-5528-4745-a95c-487d5532991b	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_query-groups}	query-groups	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
3e4f23ed-fc72-403f-a675-3e9641aeb1a6	4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	t	${role_view-profile}	view-profile	master	4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	\N
43a803f1-931f-4c65-98b6-d741c5c00170	4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	t	${role_manage-account}	manage-account	master	4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	\N
683efa2a-5c8e-4f8e-a3ba-f8c95a50cd8a	4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	t	${role_manage-account-links}	manage-account-links	master	4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	\N
af240059-50b6-475d-bae5-3c979097da0d	e865f20a-8b9f-49dd-84e3-f2b6b4468a55	t	${role_read-token}	read-token	master	e865f20a-8b9f-49dd-84e3-f2b6b4468a55	\N
69124c8f-18d5-4c73-9e6c-e62233b2e619	31531d43-30cf-4f40-8b04-2151b613e54a	t	${role_impersonation}	impersonation	master	31531d43-30cf-4f40-8b04-2151b613e54a	\N
b7b345a1-94a2-45ba-ad53-43b02bde60ae	master	f	${role_offline-access}	offline_access	master	\N	master
b8933881-d2f6-4ae6-9cde-122f10b89f20	master	f	${role_uma_authorization}	uma_authorization	master	\N	master
\.


--
-- Data for Name: migration_model; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.migration_model (id, version) FROM stdin;
SINGLETON	4.6.0
\.


--
-- Data for Name: offline_client_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.offline_client_session (user_session_id, client_id, offline_flag, "timestamp", data, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: offline_user_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.offline_user_session (user_session_id, user_id, realm_id, created_on, offline_flag, data, last_session_refresh) FROM stdin;
\.


--
-- Data for Name: policy_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.policy_config (policy_id, name, value) FROM stdin;
\.


--
-- Data for Name: protocol_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.protocol_mapper (id, name, protocol, protocol_mapper_name, client_id, client_scope_id) FROM stdin;
0f57f462-456e-40b0-9ad3-c8db8293160a	locale	openid-connect	oidc-usermodel-attribute-mapper	7e747e82-a68b-46a8-a952-11e2b6f34a1b	\N
82f6e09e-799b-45d2-93ed-f6cbf28bf72e	role list	saml	saml-role-list-mapper	\N	f806fc10-7e18-4823-8c40-e610cc7b3f52
92c6094d-5522-4fa0-b181-4638da3c67a1	full name	openid-connect	oidc-full-name-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
1950e052-4c04-4c8c-bd63-612a24fd35fe	family name	openid-connect	oidc-usermodel-property-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
43035921-3635-43fe-8b77-befd9f9a4392	given name	openid-connect	oidc-usermodel-property-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
04ae8878-1382-4603-abe6-6d5e9f0b8737	middle name	openid-connect	oidc-usermodel-attribute-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
b5cd4c51-2884-4a34-aef7-c09ae95eacbf	nickname	openid-connect	oidc-usermodel-attribute-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
7e30b077-bb65-4e09-9368-9333b6b227c2	username	openid-connect	oidc-usermodel-property-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
24f3db89-1cb5-4064-8f80-7973c13dbd44	profile	openid-connect	oidc-usermodel-attribute-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
bc27be22-f236-4843-9dd7-583a587e0985	picture	openid-connect	oidc-usermodel-attribute-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
b6cbcb08-8a89-4ddf-aa99-0af77c50a4d8	website	openid-connect	oidc-usermodel-attribute-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
9bf8e006-9d3c-43a6-b1cb-6274fcf68134	gender	openid-connect	oidc-usermodel-attribute-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
146bfe5f-e98e-4c94-8c35-88730ed24f16	birthdate	openid-connect	oidc-usermodel-attribute-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
1068ab6e-4063-48aa-a8a5-d1df45d49434	zoneinfo	openid-connect	oidc-usermodel-attribute-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
d3f83f3e-447d-4f9a-ae73-706cd1bd7e7a	locale	openid-connect	oidc-usermodel-attribute-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
6dfb0921-8c15-4f91-b004-d641958748e6	updated at	openid-connect	oidc-usermodel-attribute-mapper	\N	8580c6c6-4118-4bc8-8935-777a64d9de99
2d6c2b31-6a9c-4abc-8f35-c2c8f77e1211	email	openid-connect	oidc-usermodel-property-mapper	\N	920add0f-ae22-4b55-8494-283156626879
b5ccd52b-2a27-416b-a4e6-db9e83fb8a39	email verified	openid-connect	oidc-usermodel-property-mapper	\N	920add0f-ae22-4b55-8494-283156626879
81b316a6-b6b6-447d-ab07-28f588e6a20e	address	openid-connect	oidc-address-mapper	\N	99895a6e-497a-46cd-8b5d-a9a26344509f
81984ea7-77ec-4b1d-ba30-95a88fd1ab70	phone number	openid-connect	oidc-usermodel-attribute-mapper	\N	c25b82c3-20a8-45fb-976e-8160fb5a79b8
5d367462-573e-47fb-abfc-7376116d5890	phone number verified	openid-connect	oidc-usermodel-attribute-mapper	\N	c25b82c3-20a8-45fb-976e-8160fb5a79b8
b32161e5-36a1-470d-9bb3-da4725fc2a72	realm roles	openid-connect	oidc-usermodel-realm-role-mapper	\N	1409bcea-a67b-4799-94b2-2543b59c9d45
eff6e71f-0528-4310-9ffc-bd12be64c10c	client roles	openid-connect	oidc-usermodel-client-role-mapper	\N	1409bcea-a67b-4799-94b2-2543b59c9d45
28c55f89-21f6-4213-a383-37bde032b1c9	audience resolve	openid-connect	oidc-audience-resolve-mapper	\N	1409bcea-a67b-4799-94b2-2543b59c9d45
19fe9eb7-ff50-4f87-9629-521d77d3a7c8	allowed web origins	openid-connect	oidc-allowed-origins-mapper	\N	81b5be5e-373c-47e0-ace8-299254218d88
56974322-3b4d-4318-be5f-f8bfdb684b92	upn	openid-connect	oidc-usermodel-property-mapper	\N	112556c8-d6c3-4620-a381-691d965c8165
a5601605-44fb-4027-8b44-c8fcd0cf7125	groups	openid-connect	oidc-usermodel-realm-role-mapper	\N	112556c8-d6c3-4620-a381-691d965c8165
48ecca9b-7fdd-459d-8d34-c767cc0f53b6	groups	openid-connect	oidc-group-membership-mapper	a5d95e2d-4a79-4244-ba5c-e2f688b8431b	\N
\.


--
-- Data for Name: protocol_mapper_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.protocol_mapper_config (protocol_mapper_id, value, name) FROM stdin;
0f57f462-456e-40b0-9ad3-c8db8293160a	true	userinfo.token.claim
0f57f462-456e-40b0-9ad3-c8db8293160a	locale	user.attribute
0f57f462-456e-40b0-9ad3-c8db8293160a	true	id.token.claim
0f57f462-456e-40b0-9ad3-c8db8293160a	true	access.token.claim
0f57f462-456e-40b0-9ad3-c8db8293160a	locale	claim.name
0f57f462-456e-40b0-9ad3-c8db8293160a	String	jsonType.label
82f6e09e-799b-45d2-93ed-f6cbf28bf72e	false	single
82f6e09e-799b-45d2-93ed-f6cbf28bf72e	Basic	attribute.nameformat
82f6e09e-799b-45d2-93ed-f6cbf28bf72e	Role	attribute.name
92c6094d-5522-4fa0-b181-4638da3c67a1	true	userinfo.token.claim
92c6094d-5522-4fa0-b181-4638da3c67a1	true	id.token.claim
92c6094d-5522-4fa0-b181-4638da3c67a1	true	access.token.claim
1950e052-4c04-4c8c-bd63-612a24fd35fe	true	userinfo.token.claim
1950e052-4c04-4c8c-bd63-612a24fd35fe	lastName	user.attribute
1950e052-4c04-4c8c-bd63-612a24fd35fe	true	id.token.claim
1950e052-4c04-4c8c-bd63-612a24fd35fe	true	access.token.claim
1950e052-4c04-4c8c-bd63-612a24fd35fe	family_name	claim.name
1950e052-4c04-4c8c-bd63-612a24fd35fe	String	jsonType.label
43035921-3635-43fe-8b77-befd9f9a4392	true	userinfo.token.claim
43035921-3635-43fe-8b77-befd9f9a4392	firstName	user.attribute
43035921-3635-43fe-8b77-befd9f9a4392	true	id.token.claim
43035921-3635-43fe-8b77-befd9f9a4392	true	access.token.claim
43035921-3635-43fe-8b77-befd9f9a4392	given_name	claim.name
43035921-3635-43fe-8b77-befd9f9a4392	String	jsonType.label
04ae8878-1382-4603-abe6-6d5e9f0b8737	true	userinfo.token.claim
04ae8878-1382-4603-abe6-6d5e9f0b8737	middleName	user.attribute
04ae8878-1382-4603-abe6-6d5e9f0b8737	true	id.token.claim
04ae8878-1382-4603-abe6-6d5e9f0b8737	true	access.token.claim
04ae8878-1382-4603-abe6-6d5e9f0b8737	middle_name	claim.name
04ae8878-1382-4603-abe6-6d5e9f0b8737	String	jsonType.label
b5cd4c51-2884-4a34-aef7-c09ae95eacbf	true	userinfo.token.claim
b5cd4c51-2884-4a34-aef7-c09ae95eacbf	nickname	user.attribute
b5cd4c51-2884-4a34-aef7-c09ae95eacbf	true	id.token.claim
b5cd4c51-2884-4a34-aef7-c09ae95eacbf	true	access.token.claim
b5cd4c51-2884-4a34-aef7-c09ae95eacbf	nickname	claim.name
b5cd4c51-2884-4a34-aef7-c09ae95eacbf	String	jsonType.label
7e30b077-bb65-4e09-9368-9333b6b227c2	true	userinfo.token.claim
7e30b077-bb65-4e09-9368-9333b6b227c2	username	user.attribute
7e30b077-bb65-4e09-9368-9333b6b227c2	true	id.token.claim
7e30b077-bb65-4e09-9368-9333b6b227c2	true	access.token.claim
7e30b077-bb65-4e09-9368-9333b6b227c2	preferred_username	claim.name
7e30b077-bb65-4e09-9368-9333b6b227c2	String	jsonType.label
24f3db89-1cb5-4064-8f80-7973c13dbd44	true	userinfo.token.claim
24f3db89-1cb5-4064-8f80-7973c13dbd44	profile	user.attribute
24f3db89-1cb5-4064-8f80-7973c13dbd44	true	id.token.claim
24f3db89-1cb5-4064-8f80-7973c13dbd44	true	access.token.claim
24f3db89-1cb5-4064-8f80-7973c13dbd44	profile	claim.name
24f3db89-1cb5-4064-8f80-7973c13dbd44	String	jsonType.label
bc27be22-f236-4843-9dd7-583a587e0985	true	userinfo.token.claim
bc27be22-f236-4843-9dd7-583a587e0985	picture	user.attribute
bc27be22-f236-4843-9dd7-583a587e0985	true	id.token.claim
bc27be22-f236-4843-9dd7-583a587e0985	true	access.token.claim
bc27be22-f236-4843-9dd7-583a587e0985	picture	claim.name
bc27be22-f236-4843-9dd7-583a587e0985	String	jsonType.label
b6cbcb08-8a89-4ddf-aa99-0af77c50a4d8	true	userinfo.token.claim
b6cbcb08-8a89-4ddf-aa99-0af77c50a4d8	website	user.attribute
b6cbcb08-8a89-4ddf-aa99-0af77c50a4d8	true	id.token.claim
b6cbcb08-8a89-4ddf-aa99-0af77c50a4d8	true	access.token.claim
b6cbcb08-8a89-4ddf-aa99-0af77c50a4d8	website	claim.name
b6cbcb08-8a89-4ddf-aa99-0af77c50a4d8	String	jsonType.label
9bf8e006-9d3c-43a6-b1cb-6274fcf68134	true	userinfo.token.claim
9bf8e006-9d3c-43a6-b1cb-6274fcf68134	gender	user.attribute
9bf8e006-9d3c-43a6-b1cb-6274fcf68134	true	id.token.claim
9bf8e006-9d3c-43a6-b1cb-6274fcf68134	true	access.token.claim
9bf8e006-9d3c-43a6-b1cb-6274fcf68134	gender	claim.name
9bf8e006-9d3c-43a6-b1cb-6274fcf68134	String	jsonType.label
146bfe5f-e98e-4c94-8c35-88730ed24f16	true	userinfo.token.claim
146bfe5f-e98e-4c94-8c35-88730ed24f16	birthdate	user.attribute
146bfe5f-e98e-4c94-8c35-88730ed24f16	true	id.token.claim
146bfe5f-e98e-4c94-8c35-88730ed24f16	true	access.token.claim
146bfe5f-e98e-4c94-8c35-88730ed24f16	birthdate	claim.name
146bfe5f-e98e-4c94-8c35-88730ed24f16	String	jsonType.label
1068ab6e-4063-48aa-a8a5-d1df45d49434	true	userinfo.token.claim
1068ab6e-4063-48aa-a8a5-d1df45d49434	zoneinfo	user.attribute
1068ab6e-4063-48aa-a8a5-d1df45d49434	true	id.token.claim
1068ab6e-4063-48aa-a8a5-d1df45d49434	true	access.token.claim
1068ab6e-4063-48aa-a8a5-d1df45d49434	zoneinfo	claim.name
1068ab6e-4063-48aa-a8a5-d1df45d49434	String	jsonType.label
d3f83f3e-447d-4f9a-ae73-706cd1bd7e7a	true	userinfo.token.claim
d3f83f3e-447d-4f9a-ae73-706cd1bd7e7a	locale	user.attribute
d3f83f3e-447d-4f9a-ae73-706cd1bd7e7a	true	id.token.claim
d3f83f3e-447d-4f9a-ae73-706cd1bd7e7a	true	access.token.claim
d3f83f3e-447d-4f9a-ae73-706cd1bd7e7a	locale	claim.name
d3f83f3e-447d-4f9a-ae73-706cd1bd7e7a	String	jsonType.label
6dfb0921-8c15-4f91-b004-d641958748e6	true	userinfo.token.claim
6dfb0921-8c15-4f91-b004-d641958748e6	updatedAt	user.attribute
6dfb0921-8c15-4f91-b004-d641958748e6	true	id.token.claim
6dfb0921-8c15-4f91-b004-d641958748e6	true	access.token.claim
6dfb0921-8c15-4f91-b004-d641958748e6	updated_at	claim.name
6dfb0921-8c15-4f91-b004-d641958748e6	String	jsonType.label
2d6c2b31-6a9c-4abc-8f35-c2c8f77e1211	true	userinfo.token.claim
2d6c2b31-6a9c-4abc-8f35-c2c8f77e1211	email	user.attribute
2d6c2b31-6a9c-4abc-8f35-c2c8f77e1211	true	id.token.claim
2d6c2b31-6a9c-4abc-8f35-c2c8f77e1211	true	access.token.claim
2d6c2b31-6a9c-4abc-8f35-c2c8f77e1211	email	claim.name
2d6c2b31-6a9c-4abc-8f35-c2c8f77e1211	String	jsonType.label
b5ccd52b-2a27-416b-a4e6-db9e83fb8a39	true	userinfo.token.claim
b5ccd52b-2a27-416b-a4e6-db9e83fb8a39	emailVerified	user.attribute
b5ccd52b-2a27-416b-a4e6-db9e83fb8a39	true	id.token.claim
b5ccd52b-2a27-416b-a4e6-db9e83fb8a39	true	access.token.claim
b5ccd52b-2a27-416b-a4e6-db9e83fb8a39	email_verified	claim.name
b5ccd52b-2a27-416b-a4e6-db9e83fb8a39	boolean	jsonType.label
81b316a6-b6b6-447d-ab07-28f588e6a20e	formatted	user.attribute.formatted
81b316a6-b6b6-447d-ab07-28f588e6a20e	country	user.attribute.country
81b316a6-b6b6-447d-ab07-28f588e6a20e	postal_code	user.attribute.postal_code
81b316a6-b6b6-447d-ab07-28f588e6a20e	true	userinfo.token.claim
81b316a6-b6b6-447d-ab07-28f588e6a20e	street	user.attribute.street
81b316a6-b6b6-447d-ab07-28f588e6a20e	true	id.token.claim
81b316a6-b6b6-447d-ab07-28f588e6a20e	region	user.attribute.region
81b316a6-b6b6-447d-ab07-28f588e6a20e	true	access.token.claim
81b316a6-b6b6-447d-ab07-28f588e6a20e	locality	user.attribute.locality
81984ea7-77ec-4b1d-ba30-95a88fd1ab70	true	userinfo.token.claim
81984ea7-77ec-4b1d-ba30-95a88fd1ab70	phoneNumber	user.attribute
81984ea7-77ec-4b1d-ba30-95a88fd1ab70	true	id.token.claim
81984ea7-77ec-4b1d-ba30-95a88fd1ab70	true	access.token.claim
81984ea7-77ec-4b1d-ba30-95a88fd1ab70	phone_number	claim.name
81984ea7-77ec-4b1d-ba30-95a88fd1ab70	String	jsonType.label
5d367462-573e-47fb-abfc-7376116d5890	true	userinfo.token.claim
5d367462-573e-47fb-abfc-7376116d5890	phoneNumberVerified	user.attribute
5d367462-573e-47fb-abfc-7376116d5890	true	id.token.claim
5d367462-573e-47fb-abfc-7376116d5890	true	access.token.claim
5d367462-573e-47fb-abfc-7376116d5890	phone_number_verified	claim.name
5d367462-573e-47fb-abfc-7376116d5890	boolean	jsonType.label
b32161e5-36a1-470d-9bb3-da4725fc2a72	true	multivalued
b32161e5-36a1-470d-9bb3-da4725fc2a72	foo	user.attribute
b32161e5-36a1-470d-9bb3-da4725fc2a72	true	access.token.claim
b32161e5-36a1-470d-9bb3-da4725fc2a72	realm_access.roles	claim.name
b32161e5-36a1-470d-9bb3-da4725fc2a72	String	jsonType.label
eff6e71f-0528-4310-9ffc-bd12be64c10c	true	multivalued
eff6e71f-0528-4310-9ffc-bd12be64c10c	foo	user.attribute
eff6e71f-0528-4310-9ffc-bd12be64c10c	true	access.token.claim
eff6e71f-0528-4310-9ffc-bd12be64c10c	resource_access.${client_id}.roles	claim.name
eff6e71f-0528-4310-9ffc-bd12be64c10c	String	jsonType.label
56974322-3b4d-4318-be5f-f8bfdb684b92	true	userinfo.token.claim
56974322-3b4d-4318-be5f-f8bfdb684b92	username	user.attribute
56974322-3b4d-4318-be5f-f8bfdb684b92	true	id.token.claim
56974322-3b4d-4318-be5f-f8bfdb684b92	true	access.token.claim
56974322-3b4d-4318-be5f-f8bfdb684b92	upn	claim.name
56974322-3b4d-4318-be5f-f8bfdb684b92	String	jsonType.label
a5601605-44fb-4027-8b44-c8fcd0cf7125	true	multivalued
a5601605-44fb-4027-8b44-c8fcd0cf7125	foo	user.attribute
a5601605-44fb-4027-8b44-c8fcd0cf7125	true	id.token.claim
a5601605-44fb-4027-8b44-c8fcd0cf7125	true	access.token.claim
a5601605-44fb-4027-8b44-c8fcd0cf7125	groups	claim.name
a5601605-44fb-4027-8b44-c8fcd0cf7125	String	jsonType.label
48ecca9b-7fdd-459d-8d34-c767cc0f53b6	false	full.path
48ecca9b-7fdd-459d-8d34-c767cc0f53b6	true	id.token.claim
48ecca9b-7fdd-459d-8d34-c767cc0f53b6	true	access.token.claim
48ecca9b-7fdd-459d-8d34-c767cc0f53b6	groups	claim.name
48ecca9b-7fdd-459d-8d34-c767cc0f53b6	true	userinfo.token.claim
\.


--
-- Data for Name: realm; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm (id, access_code_lifespan, user_action_lifespan, access_token_lifespan, account_theme, admin_theme, email_theme, enabled, events_enabled, events_expiration, login_theme, name, not_before, password_policy, registration_allowed, remember_me, reset_password_allowed, social, ssl_required, sso_idle_timeout, sso_max_lifespan, update_profile_on_soc_login, verify_email, master_admin_client, login_lifespan, internationalization_enabled, default_locale, reg_email_as_username, admin_events_enabled, admin_events_details_enabled, edit_username_allowed, otp_policy_counter, otp_policy_window, otp_policy_period, otp_policy_digits, otp_policy_alg, otp_policy_type, browser_flow, registration_flow, direct_grant_flow, reset_credentials_flow, client_auth_flow, offline_session_idle_timeout, revoke_refresh_token, access_token_life_implicit, login_with_email_allowed, duplicate_emails_allowed, docker_auth_flow, refresh_token_max_reuse, allow_user_managed_access, sso_max_lifespan_remember_me, sso_idle_timeout_remember_me) FROM stdin;
master	60	300	60	\N	\N	\N	t	f	0	\N	master	0	\N	f	f	f	f	EXTERNAL	1800	36000	f	f	31531d43-30cf-4f40-8b04-2151b613e54a	1800	f	\N	f	f	f	f	0	1	30	6	HmacSHA1	totp	3b20e7fd-478b-40ec-83dd-818940deeeee	9f301b6f-1ca1-4296-bd33-7203097bf042	0792121c-83a1-4d8e-9d11-6fdcfb4abdef	2fe63f14-bc2b-4284-8bdd-1e55aba0fd7d	5a7a0b79-3443-4924-85c3-97121f77915d	2592000	f	900	t	f	4d694536-cbc9-4973-89c6-23bb91a2588a	0	f	0	0
\.


--
-- Data for Name: realm_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_attribute (name, value, realm_id) FROM stdin;
_browser_header.contentSecurityPolicyReportOnly		master
_browser_header.xContentTypeOptions	nosniff	master
_browser_header.xRobotsTag	none	master
_browser_header.xFrameOptions	SAMEORIGIN	master
_browser_header.contentSecurityPolicy	frame-src 'self'; frame-ancestors 'self'; object-src 'none';	master
_browser_header.xXSSProtection	1; mode=block	master
_browser_header.strictTransportSecurity	max-age=31536000; includeSubDomains	master
bruteForceProtected	false	master
permanentLockout	false	master
maxFailureWaitSeconds	900	master
minimumQuickLoginWaitSeconds	60	master
waitIncrementSeconds	60	master
quickLoginCheckMilliSeconds	1000	master
maxDeltaTimeSeconds	43200	master
failureFactor	30	master
displayName	Keycloak	master
displayNameHtml	<div class="kc-logo-text"><span>Keycloak</span></div>	master
offlineSessionMaxLifespanEnabled	false	master
offlineSessionMaxLifespan	5184000	master
\.


--
-- Data for Name: realm_default_groups; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_default_groups (realm_id, group_id) FROM stdin;
\.


--
-- Data for Name: realm_default_roles; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_default_roles (realm_id, role_id) FROM stdin;
master	b7b345a1-94a2-45ba-ad53-43b02bde60ae
master	b8933881-d2f6-4ae6-9cde-122f10b89f20
\.


--
-- Data for Name: realm_enabled_event_types; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_enabled_event_types (realm_id, value) FROM stdin;
\.


--
-- Data for Name: realm_events_listeners; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_events_listeners (realm_id, value) FROM stdin;
master	jboss-logging
\.


--
-- Data for Name: realm_required_credential; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_required_credential (type, form_label, input, secret, realm_id) FROM stdin;
password	password	t	t	master
\.


--
-- Data for Name: realm_smtp_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_smtp_config (realm_id, value, name) FROM stdin;
\.


--
-- Data for Name: realm_supported_locales; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.realm_supported_locales (realm_id, value) FROM stdin;
\.


--
-- Data for Name: redirect_uris; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.redirect_uris (client_id, value) FROM stdin;
4a2e2b71-72ff-4798-a1ba-11c45bd9c9d6	/auth/realms/master/account/*
7e747e82-a68b-46a8-a952-11e2b6f34a1b	/auth/admin/master/console/*
a5d95e2d-4a79-4244-ba5c-e2f688b8431b	/broker/oidc-customer/*
\.


--
-- Data for Name: required_action_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.required_action_config (required_action_id, value, name) FROM stdin;
\.


--
-- Data for Name: required_action_provider; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.required_action_provider (id, alias, name, realm_id, enabled, default_action, provider_id, priority) FROM stdin;
2520b5ac-ab2c-49f5-9e96-11104142541c	VERIFY_EMAIL	Verify Email	master	t	f	VERIFY_EMAIL	50
f7389fe7-47c4-4a97-a455-51e84144f91e	UPDATE_PROFILE	Update Profile	master	t	f	UPDATE_PROFILE	40
2a82a645-f6f0-4833-ba1e-f9545f0f53ff	CONFIGURE_TOTP	Configure OTP	master	t	f	CONFIGURE_TOTP	10
40b49baf-1e12-4c9b-853c-1c8a7e57ec37	UPDATE_PASSWORD	Update Password	master	t	f	UPDATE_PASSWORD	30
8199ba89-3689-407c-a533-2ecbbd0abdf4	terms_and_conditions	Terms and Conditions	master	f	f	terms_and_conditions	20
\.


--
-- Data for Name: resource_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_attribute (id, name, value, resource_id) FROM stdin;
\.


--
-- Data for Name: resource_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_policy (resource_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_scope (resource_id, scope_id) FROM stdin;
\.


--
-- Data for Name: resource_server; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server (id, allow_rs_remote_mgmt, policy_enforce_mode) FROM stdin;
\.


--
-- Data for Name: resource_server_perm_ticket; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_perm_ticket (id, owner, requester, created_timestamp, granted_timestamp, resource_id, scope_id, resource_server_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_server_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_policy (id, name, description, type, decision_strategy, logic, resource_server_id, owner) FROM stdin;
\.


--
-- Data for Name: resource_server_resource; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_resource (id, name, type, icon_uri, owner, resource_server_id, owner_managed_access, display_name) FROM stdin;
\.


--
-- Data for Name: resource_server_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_server_scope (id, name, icon_uri, resource_server_id, display_name) FROM stdin;
\.


--
-- Data for Name: resource_uris; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.resource_uris (resource_id, value) FROM stdin;
\.


--
-- Data for Name: role_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.role_attribute (id, role_id, name, value) FROM stdin;
\.


--
-- Data for Name: scope_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.scope_mapping (client_id, role_id) FROM stdin;
\.


--
-- Data for Name: scope_policy; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.scope_policy (scope_id, policy_id) FROM stdin;
\.


--
-- Data for Name: user_attribute; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_attribute (name, value, user_id, id) FROM stdin;
\.


--
-- Data for Name: user_consent; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_consent (id, client_id, user_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: user_consent_client_scope; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_consent_client_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: user_entity; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_entity (id, email, email_constraint, email_verified, enabled, federation_link, first_name, last_name, realm_id, username, created_timestamp, service_account_client_link, not_before) FROM stdin;
4c16dcbf-12d8-40d3-8879-a24882e11f06	\N	d49041fe-683d-4966-b29a-8d787013899d	f	t	\N	\N	\N	master	admin	1567772509740	\N	0
64c0212e-85bd-4eda-90d9-a5fc22eafb68	fredbi@yahoo.com	fredbi@yahoo.com	t	t	\N	Frédéric	BIDON	master	frederic-oidc	1567776492548	\N	1567797284
\.


--
-- Data for Name: user_federation_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_config (user_federation_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_mapper (id, name, federation_provider_id, federation_mapper_type, realm_id) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper_config; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_mapper_config (user_federation_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_provider; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_federation_provider (id, changed_sync_period, display_name, full_sync_period, last_sync, priority, provider_name, realm_id) FROM stdin;
\.


--
-- Data for Name: user_group_membership; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_group_membership (group_id, user_id) FROM stdin;
5b89a816-6556-4a76-8a4f-b2e42c541860	64c0212e-85bd-4eda-90d9-a5fc22eafb68
b46671c7-4bc5-43ce-802b-8146d0d14971	64c0212e-85bd-4eda-90d9-a5fc22eafb68
\.


--
-- Data for Name: user_required_action; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_required_action (user_id, required_action) FROM stdin;
\.


--
-- Data for Name: user_role_mapping; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_role_mapping (role_id, user_id) FROM stdin;
b8933881-d2f6-4ae6-9cde-122f10b89f20	4c16dcbf-12d8-40d3-8879-a24882e11f06
43a803f1-931f-4c65-98b6-d741c5c00170	4c16dcbf-12d8-40d3-8879-a24882e11f06
b7b345a1-94a2-45ba-ad53-43b02bde60ae	4c16dcbf-12d8-40d3-8879-a24882e11f06
3e4f23ed-fc72-403f-a675-3e9641aeb1a6	4c16dcbf-12d8-40d3-8879-a24882e11f06
c69bbd4a-30d8-4fc3-8c96-d1aa45e8cb86	4c16dcbf-12d8-40d3-8879-a24882e11f06
b8933881-d2f6-4ae6-9cde-122f10b89f20	64c0212e-85bd-4eda-90d9-a5fc22eafb68
43a803f1-931f-4c65-98b6-d741c5c00170	64c0212e-85bd-4eda-90d9-a5fc22eafb68
b7b345a1-94a2-45ba-ad53-43b02bde60ae	64c0212e-85bd-4eda-90d9-a5fc22eafb68
3e4f23ed-fc72-403f-a675-3e9641aeb1a6	64c0212e-85bd-4eda-90d9-a5fc22eafb68
\.


--
-- Data for Name: user_session; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_session (id, auth_method, ip_address, last_session_refresh, login_username, realm_id, remember_me, started, user_id, user_session_state, broker_session_id, broker_user_id) FROM stdin;
\.


--
-- Data for Name: user_session_note; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.user_session_note (user_session, name, value) FROM stdin;
\.


--
-- Data for Name: username_login_failure; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.username_login_failure (realm_id, username, failed_login_not_before, last_failure, last_ip_failure, num_failures) FROM stdin;
\.


--
-- Data for Name: web_origins; Type: TABLE DATA; Schema: public; Owner: dbuser
--

COPY public.web_origins (client_id, value) FROM stdin;
\.


--
-- Name: username_login_failure CONSTRAINT_17-2; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.username_login_failure
    ADD CONSTRAINT "CONSTRAINT_17-2" PRIMARY KEY (realm_id, username);


--
-- Name: keycloak_role UK_J3RWUVD56ONTGSUHOGM184WW2-2; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT "UK_J3RWUVD56ONTGSUHOGM184WW2-2" UNIQUE (name, client_realm_constraint);


--
-- Name: client_auth_flow_bindings c_cli_flow_bind; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_auth_flow_bindings
    ADD CONSTRAINT c_cli_flow_bind PRIMARY KEY (client_id, binding_name);


--
-- Name: client_scope_client c_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT c_cli_scope_bind PRIMARY KEY (client_id, scope_id);


--
-- Name: client_initial_access cnstr_client_init_acc_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT cnstr_client_init_acc_pk PRIMARY KEY (id);


--
-- Name: realm_default_groups con_group_id_def_groups; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT con_group_id_def_groups UNIQUE (group_id);


--
-- Name: broker_link constr_broker_link_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.broker_link
    ADD CONSTRAINT constr_broker_link_pk PRIMARY KEY (identity_provider, user_id);


--
-- Name: client_user_session_note constr_cl_usr_ses_note; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_user_session_note
    ADD CONSTRAINT constr_cl_usr_ses_note PRIMARY KEY (client_session, name);


--
-- Name: client_default_roles constr_client_default_roles; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT constr_client_default_roles PRIMARY KEY (client_id, role_id);


--
-- Name: component_config constr_component_config_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT constr_component_config_pk PRIMARY KEY (id);


--
-- Name: component constr_component_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT constr_component_pk PRIMARY KEY (id);


--
-- Name: fed_user_required_action constr_fed_required_action; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_required_action
    ADD CONSTRAINT constr_fed_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: fed_user_attribute constr_fed_user_attr_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_attribute
    ADD CONSTRAINT constr_fed_user_attr_pk PRIMARY KEY (id);


--
-- Name: fed_user_consent constr_fed_user_consent_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_consent
    ADD CONSTRAINT constr_fed_user_consent_pk PRIMARY KEY (id);


--
-- Name: fed_user_credential constr_fed_user_cred_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_credential
    ADD CONSTRAINT constr_fed_user_cred_pk PRIMARY KEY (id);


--
-- Name: fed_user_group_membership constr_fed_user_group; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_group_membership
    ADD CONSTRAINT constr_fed_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: fed_user_role_mapping constr_fed_user_role; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_role_mapping
    ADD CONSTRAINT constr_fed_user_role PRIMARY KEY (role_id, user_id);


--
-- Name: federated_user constr_federated_user; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.federated_user
    ADD CONSTRAINT constr_federated_user PRIMARY KEY (id);


--
-- Name: realm_default_groups constr_realm_default_groups; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT constr_realm_default_groups PRIMARY KEY (realm_id, group_id);


--
-- Name: realm_enabled_event_types constr_realm_enabl_event_types; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT constr_realm_enabl_event_types PRIMARY KEY (realm_id, value);


--
-- Name: realm_events_listeners constr_realm_events_listeners; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT constr_realm_events_listeners PRIMARY KEY (realm_id, value);


--
-- Name: realm_supported_locales constr_realm_supported_locales; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT constr_realm_supported_locales PRIMARY KEY (realm_id, value);


--
-- Name: identity_provider constraint_2b; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT constraint_2b PRIMARY KEY (internal_id);


--
-- Name: client_attributes constraint_3c; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT constraint_3c PRIMARY KEY (client_id, name);


--
-- Name: event_entity constraint_4; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.event_entity
    ADD CONSTRAINT constraint_4 PRIMARY KEY (id);


--
-- Name: federated_identity constraint_40; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT constraint_40 PRIMARY KEY (identity_provider, user_id);


--
-- Name: realm constraint_4a; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT constraint_4a PRIMARY KEY (id);


--
-- Name: client_session_role constraint_5; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_role
    ADD CONSTRAINT constraint_5 PRIMARY KEY (client_session, role_id);


--
-- Name: user_session constraint_57; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_session
    ADD CONSTRAINT constraint_57 PRIMARY KEY (id);


--
-- Name: user_federation_provider constraint_5c; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT constraint_5c PRIMARY KEY (id);


--
-- Name: client_session_note constraint_5e; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_note
    ADD CONSTRAINT constraint_5e PRIMARY KEY (client_session, name);


--
-- Name: client constraint_7; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT constraint_7 PRIMARY KEY (id);


--
-- Name: client_session constraint_8; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session
    ADD CONSTRAINT constraint_8 PRIMARY KEY (id);


--
-- Name: scope_mapping constraint_81; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT constraint_81 PRIMARY KEY (client_id, role_id);


--
-- Name: client_node_registrations constraint_84; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT constraint_84 PRIMARY KEY (client_id, name);


--
-- Name: realm_attribute constraint_9; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT constraint_9 PRIMARY KEY (name, realm_id);


--
-- Name: realm_required_credential constraint_92; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT constraint_92 PRIMARY KEY (realm_id, type);


--
-- Name: keycloak_role constraint_a; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT constraint_a PRIMARY KEY (id);


--
-- Name: admin_event_entity constraint_admin_event_entity; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.admin_event_entity
    ADD CONSTRAINT constraint_admin_event_entity PRIMARY KEY (id);


--
-- Name: authenticator_config_entry constraint_auth_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authenticator_config_entry
    ADD CONSTRAINT constraint_auth_cfg_pk PRIMARY KEY (authenticator_id, name);


--
-- Name: authentication_execution constraint_auth_exec_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT constraint_auth_exec_pk PRIMARY KEY (id);


--
-- Name: authentication_flow constraint_auth_flow_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT constraint_auth_flow_pk PRIMARY KEY (id);


--
-- Name: authenticator_config constraint_auth_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT constraint_auth_pk PRIMARY KEY (id);


--
-- Name: client_session_auth_status constraint_auth_status_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_auth_status
    ADD CONSTRAINT constraint_auth_status_pk PRIMARY KEY (client_session, authenticator);


--
-- Name: user_role_mapping constraint_c; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT constraint_c PRIMARY KEY (role_id, user_id);


--
-- Name: composite_role constraint_composite_role; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT constraint_composite_role PRIMARY KEY (composite, child_role);


--
-- Name: credential_attribute constraint_credential_attr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential_attribute
    ADD CONSTRAINT constraint_credential_attr PRIMARY KEY (id);


--
-- Name: client_session_prot_mapper constraint_cs_pmp_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_prot_mapper
    ADD CONSTRAINT constraint_cs_pmp_pk PRIMARY KEY (client_session, protocol_mapper_id);


--
-- Name: identity_provider_config constraint_d; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT constraint_d PRIMARY KEY (identity_provider_id, name);


--
-- Name: policy_config constraint_dpc; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT constraint_dpc PRIMARY KEY (policy_id, name);


--
-- Name: realm_smtp_config constraint_e; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT constraint_e PRIMARY KEY (realm_id, name);


--
-- Name: credential constraint_f; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT constraint_f PRIMARY KEY (id);


--
-- Name: user_federation_config constraint_f9; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT constraint_f9 PRIMARY KEY (user_federation_provider_id, name);


--
-- Name: resource_server_perm_ticket constraint_fapmt; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT constraint_fapmt PRIMARY KEY (id);


--
-- Name: resource_server_resource constraint_farsr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT constraint_farsr PRIMARY KEY (id);


--
-- Name: resource_server_policy constraint_farsrp; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT constraint_farsrp PRIMARY KEY (id);


--
-- Name: associated_policy constraint_farsrpap; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT constraint_farsrpap PRIMARY KEY (policy_id, associated_policy_id);


--
-- Name: resource_policy constraint_farsrpp; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT constraint_farsrpp PRIMARY KEY (resource_id, policy_id);


--
-- Name: resource_server_scope constraint_farsrs; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT constraint_farsrs PRIMARY KEY (id);


--
-- Name: resource_scope constraint_farsrsp; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT constraint_farsrsp PRIMARY KEY (resource_id, scope_id);


--
-- Name: scope_policy constraint_farsrsps; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT constraint_farsrsps PRIMARY KEY (scope_id, policy_id);


--
-- Name: user_entity constraint_fb; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT constraint_fb PRIMARY KEY (id);


--
-- Name: fed_credential_attribute constraint_fed_credential_attr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_credential_attribute
    ADD CONSTRAINT constraint_fed_credential_attr PRIMARY KEY (id);


--
-- Name: user_federation_mapper_config constraint_fedmapper_cfg_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT constraint_fedmapper_cfg_pm PRIMARY KEY (user_federation_mapper_id, name);


--
-- Name: user_federation_mapper constraint_fedmapperpm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT constraint_fedmapperpm PRIMARY KEY (id);


--
-- Name: fed_user_consent_cl_scope constraint_fgrntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_user_consent_cl_scope
    ADD CONSTRAINT constraint_fgrntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent_client_scope constraint_grntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT constraint_grntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent constraint_grntcsnt_pm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT constraint_grntcsnt_pm PRIMARY KEY (id);


--
-- Name: keycloak_group constraint_group; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT constraint_group PRIMARY KEY (id);


--
-- Name: group_attribute constraint_group_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT constraint_group_attribute_pk PRIMARY KEY (id);


--
-- Name: group_role_mapping constraint_group_role; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT constraint_group_role PRIMARY KEY (role_id, group_id);


--
-- Name: identity_provider_mapper constraint_idpm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT constraint_idpm PRIMARY KEY (id);


--
-- Name: idp_mapper_config constraint_idpmconfig; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT constraint_idpmconfig PRIMARY KEY (idp_mapper_id, name);


--
-- Name: migration_model constraint_migmod; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.migration_model
    ADD CONSTRAINT constraint_migmod PRIMARY KEY (id);


--
-- Name: offline_client_session constraint_offl_cl_ses_pk3; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.offline_client_session
    ADD CONSTRAINT constraint_offl_cl_ses_pk3 PRIMARY KEY (user_session_id, client_id, client_storage_provider, external_client_id, offline_flag);


--
-- Name: offline_user_session constraint_offl_us_ses_pk2; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.offline_user_session
    ADD CONSTRAINT constraint_offl_us_ses_pk2 PRIMARY KEY (user_session_id, offline_flag);


--
-- Name: protocol_mapper constraint_pcm; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT constraint_pcm PRIMARY KEY (id);


--
-- Name: protocol_mapper_config constraint_pmconfig; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT constraint_pmconfig PRIMARY KEY (protocol_mapper_id, name);


--
-- Name: realm_default_roles constraint_realm_default_roles; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT constraint_realm_default_roles PRIMARY KEY (realm_id, role_id);


--
-- Name: redirect_uris constraint_redirect_uris; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT constraint_redirect_uris PRIMARY KEY (client_id, value);


--
-- Name: required_action_config constraint_req_act_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.required_action_config
    ADD CONSTRAINT constraint_req_act_cfg_pk PRIMARY KEY (required_action_id, name);


--
-- Name: required_action_provider constraint_req_act_prv_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT constraint_req_act_prv_pk PRIMARY KEY (id);


--
-- Name: user_required_action constraint_required_action; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT constraint_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: role_attribute constraint_role_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT constraint_role_attribute_pk PRIMARY KEY (id);


--
-- Name: user_attribute constraint_user_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT constraint_user_attribute_pk PRIMARY KEY (id);


--
-- Name: user_group_membership constraint_user_group; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT constraint_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: user_session_note constraint_usn_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_session_note
    ADD CONSTRAINT constraint_usn_pk PRIMARY KEY (user_session, name);


--
-- Name: web_origins constraint_web_origins; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT constraint_web_origins PRIMARY KEY (client_id, value);


--
-- Name: client_scope_attributes pk_cl_tmpl_attr; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT pk_cl_tmpl_attr PRIMARY KEY (scope_id, name);


--
-- Name: client_scope pk_cli_template; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT pk_cli_template PRIMARY KEY (id);


--
-- Name: databasechangeloglock pk_databasechangeloglock; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.databasechangeloglock
    ADD CONSTRAINT pk_databasechangeloglock PRIMARY KEY (id);


--
-- Name: resource_server pk_resource_server; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server
    ADD CONSTRAINT pk_resource_server PRIMARY KEY (id);


--
-- Name: client_scope_role_mapping pk_template_scope; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT pk_template_scope PRIMARY KEY (scope_id, role_id);


--
-- Name: default_client_scope r_def_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT r_def_cli_scope_bind PRIMARY KEY (realm_id, scope_id);


--
-- Name: resource_attribute res_attr_pk; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT res_attr_pk PRIMARY KEY (id);


--
-- Name: keycloak_group sibling_names; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT sibling_names UNIQUE (realm_id, parent_group, name);


--
-- Name: identity_provider uk_2daelwnibji49avxsrtuf6xj33; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT uk_2daelwnibji49avxsrtuf6xj33 UNIQUE (provider_alias, realm_id);


--
-- Name: client_default_roles uk_8aelwnibji49avxsrtuf6xjow; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT uk_8aelwnibji49avxsrtuf6xjow UNIQUE (role_id);


--
-- Name: client uk_b71cjlbenv945rb6gcon438at; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT uk_b71cjlbenv945rb6gcon438at UNIQUE (realm_id, client_id);


--
-- Name: client_scope uk_cli_scope; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT uk_cli_scope UNIQUE (realm_id, name);


--
-- Name: user_entity uk_dykn684sl8up1crfei6eckhd7; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_dykn684sl8up1crfei6eckhd7 UNIQUE (realm_id, email_constraint);


--
-- Name: resource_server_resource uk_frsr6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5ha6 UNIQUE (name, owner, resource_server_id);


--
-- Name: resource_server_perm_ticket uk_frsr6t700s9v50bu18ws5pmt; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5pmt UNIQUE (owner, requester, resource_server_id, resource_id, scope_id);


--
-- Name: resource_server_policy uk_frsrpt700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT uk_frsrpt700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: resource_server_scope uk_frsrst700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT uk_frsrst700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: realm_default_roles uk_h4wpd7w4hsoolni3h0sw7btje; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT uk_h4wpd7w4hsoolni3h0sw7btje UNIQUE (role_id);


--
-- Name: user_consent uk_jkuwuvd56ontgsuhogm8uewrt; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT uk_jkuwuvd56ontgsuhogm8uewrt UNIQUE (client_id, client_storage_provider, external_client_id, user_id);


--
-- Name: realm uk_orvsdmla56612eaefiq6wl5oi; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT uk_orvsdmla56612eaefiq6wl5oi UNIQUE (name);


--
-- Name: user_entity uk_ru8tt6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_ru8tt6t700s9v50bu18ws5ha6 UNIQUE (realm_id, username);


--
-- Name: idx_assoc_pol_assoc_pol_id; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_assoc_pol_assoc_pol_id ON public.associated_policy USING btree (associated_policy_id);


--
-- Name: idx_auth_config_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_config_realm ON public.authenticator_config USING btree (realm_id);


--
-- Name: idx_auth_exec_flow; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_exec_flow ON public.authentication_execution USING btree (flow_id);


--
-- Name: idx_auth_exec_realm_flow; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_exec_realm_flow ON public.authentication_execution USING btree (realm_id, flow_id);


--
-- Name: idx_auth_flow_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_auth_flow_realm ON public.authentication_flow USING btree (realm_id);


--
-- Name: idx_cl_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_cl_clscope ON public.client_scope_client USING btree (scope_id);


--
-- Name: idx_client_def_roles_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_client_def_roles_client ON public.client_default_roles USING btree (client_id);


--
-- Name: idx_client_init_acc_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_client_init_acc_realm ON public.client_initial_access USING btree (realm_id);


--
-- Name: idx_client_session_session; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_client_session_session ON public.client_session USING btree (session_id);


--
-- Name: idx_clscope_attrs; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_attrs ON public.client_scope_attributes USING btree (scope_id);


--
-- Name: idx_clscope_cl; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_cl ON public.client_scope_client USING btree (client_id);


--
-- Name: idx_clscope_protmap; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_protmap ON public.protocol_mapper USING btree (client_scope_id);


--
-- Name: idx_clscope_role; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_clscope_role ON public.client_scope_role_mapping USING btree (scope_id);


--
-- Name: idx_compo_config_compo; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_compo_config_compo ON public.component_config USING btree (component_id);


--
-- Name: idx_component_provider_type; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_component_provider_type ON public.component USING btree (provider_type);


--
-- Name: idx_component_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_component_realm ON public.component USING btree (realm_id);


--
-- Name: idx_composite; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_composite ON public.composite_role USING btree (composite);


--
-- Name: idx_composite_child; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_composite_child ON public.composite_role USING btree (child_role);


--
-- Name: idx_credential_attr_cred; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_credential_attr_cred ON public.credential_attribute USING btree (credential_id);


--
-- Name: idx_defcls_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_defcls_realm ON public.default_client_scope USING btree (realm_id);


--
-- Name: idx_defcls_scope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_defcls_scope ON public.default_client_scope USING btree (scope_id);


--
-- Name: idx_fed_cred_attr_cred; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fed_cred_attr_cred ON public.fed_credential_attribute USING btree (credential_id);


--
-- Name: idx_fedidentity_feduser; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fedidentity_feduser ON public.federated_identity USING btree (federated_user_id);


--
-- Name: idx_fedidentity_user; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fedidentity_user ON public.federated_identity USING btree (user_id);


--
-- Name: idx_fu_attribute; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_attribute ON public.fed_user_attribute USING btree (user_id, realm_id, name);


--
-- Name: idx_fu_cnsnt_ext; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_cnsnt_ext ON public.fed_user_consent USING btree (user_id, client_storage_provider, external_client_id);


--
-- Name: idx_fu_consent; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_consent ON public.fed_user_consent USING btree (user_id, client_id);


--
-- Name: idx_fu_consent_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_consent_ru ON public.fed_user_consent USING btree (realm_id, user_id);


--
-- Name: idx_fu_credential; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_credential ON public.fed_user_credential USING btree (user_id, type);


--
-- Name: idx_fu_credential_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_credential_ru ON public.fed_user_credential USING btree (realm_id, user_id);


--
-- Name: idx_fu_group_membership; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_group_membership ON public.fed_user_group_membership USING btree (user_id, group_id);


--
-- Name: idx_fu_group_membership_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_group_membership_ru ON public.fed_user_group_membership USING btree (realm_id, user_id);


--
-- Name: idx_fu_required_action; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_required_action ON public.fed_user_required_action USING btree (user_id, required_action);


--
-- Name: idx_fu_required_action_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_required_action_ru ON public.fed_user_required_action USING btree (realm_id, user_id);


--
-- Name: idx_fu_role_mapping; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_role_mapping ON public.fed_user_role_mapping USING btree (user_id, role_id);


--
-- Name: idx_fu_role_mapping_ru; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_fu_role_mapping_ru ON public.fed_user_role_mapping USING btree (realm_id, user_id);


--
-- Name: idx_group_attr_group; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_group_attr_group ON public.group_attribute USING btree (group_id);


--
-- Name: idx_group_role_mapp_group; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_group_role_mapp_group ON public.group_role_mapping USING btree (group_id);


--
-- Name: idx_id_prov_mapp_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_id_prov_mapp_realm ON public.identity_provider_mapper USING btree (realm_id);


--
-- Name: idx_ident_prov_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_ident_prov_realm ON public.identity_provider USING btree (realm_id);


--
-- Name: idx_keycloak_role_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_keycloak_role_client ON public.keycloak_role USING btree (client);


--
-- Name: idx_keycloak_role_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_keycloak_role_realm ON public.keycloak_role USING btree (realm);


--
-- Name: idx_offline_uss_createdon; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_offline_uss_createdon ON public.offline_user_session USING btree (created_on);


--
-- Name: idx_protocol_mapper_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_protocol_mapper_client ON public.protocol_mapper USING btree (client_id);


--
-- Name: idx_realm_attr_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_attr_realm ON public.realm_attribute USING btree (realm_id);


--
-- Name: idx_realm_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_clscope ON public.client_scope USING btree (realm_id);


--
-- Name: idx_realm_def_grp_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_def_grp_realm ON public.realm_default_groups USING btree (realm_id);


--
-- Name: idx_realm_def_roles_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_def_roles_realm ON public.realm_default_roles USING btree (realm_id);


--
-- Name: idx_realm_evt_list_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_evt_list_realm ON public.realm_events_listeners USING btree (realm_id);


--
-- Name: idx_realm_evt_types_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_evt_types_realm ON public.realm_enabled_event_types USING btree (realm_id);


--
-- Name: idx_realm_master_adm_cli; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_master_adm_cli ON public.realm USING btree (master_admin_client);


--
-- Name: idx_realm_supp_local_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_realm_supp_local_realm ON public.realm_supported_locales USING btree (realm_id);


--
-- Name: idx_redir_uri_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_redir_uri_client ON public.redirect_uris USING btree (client_id);


--
-- Name: idx_req_act_prov_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_req_act_prov_realm ON public.required_action_provider USING btree (realm_id);


--
-- Name: idx_res_policy_policy; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_policy_policy ON public.resource_policy USING btree (policy_id);


--
-- Name: idx_res_scope_scope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_scope_scope ON public.resource_scope USING btree (scope_id);


--
-- Name: idx_res_serv_pol_res_serv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_serv_pol_res_serv ON public.resource_server_policy USING btree (resource_server_id);


--
-- Name: idx_res_srv_res_res_srv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_srv_res_res_srv ON public.resource_server_resource USING btree (resource_server_id);


--
-- Name: idx_res_srv_scope_res_srv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_res_srv_scope_res_srv ON public.resource_server_scope USING btree (resource_server_id);


--
-- Name: idx_role_attribute; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_role_attribute ON public.role_attribute USING btree (role_id);


--
-- Name: idx_role_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_role_clscope ON public.client_scope_role_mapping USING btree (role_id);


--
-- Name: idx_scope_mapping_role; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_scope_mapping_role ON public.scope_mapping USING btree (role_id);


--
-- Name: idx_scope_policy_policy; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_scope_policy_policy ON public.scope_policy USING btree (policy_id);


--
-- Name: idx_us_sess_id_on_cl_sess; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_us_sess_id_on_cl_sess ON public.offline_client_session USING btree (user_session_id);


--
-- Name: idx_usconsent_clscope; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usconsent_clscope ON public.user_consent_client_scope USING btree (user_consent_id);


--
-- Name: idx_user_attribute; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_attribute ON public.user_attribute USING btree (user_id);


--
-- Name: idx_user_consent; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_consent ON public.user_consent USING btree (user_id);


--
-- Name: idx_user_credential; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_credential ON public.credential USING btree (user_id);


--
-- Name: idx_user_email; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_email ON public.user_entity USING btree (email);


--
-- Name: idx_user_group_mapping; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_group_mapping ON public.user_group_membership USING btree (user_id);


--
-- Name: idx_user_reqactions; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_reqactions ON public.user_required_action USING btree (user_id);


--
-- Name: idx_user_role_mapping; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_user_role_mapping ON public.user_role_mapping USING btree (user_id);


--
-- Name: idx_usr_fed_map_fed_prv; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usr_fed_map_fed_prv ON public.user_federation_mapper USING btree (federation_provider_id);


--
-- Name: idx_usr_fed_map_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usr_fed_map_realm ON public.user_federation_mapper USING btree (realm_id);


--
-- Name: idx_usr_fed_prv_realm; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_usr_fed_prv_realm ON public.user_federation_provider USING btree (realm_id);


--
-- Name: idx_web_orig_client; Type: INDEX; Schema: public; Owner: dbuser
--

CREATE INDEX idx_web_orig_client ON public.web_origins USING btree (client_id);


--
-- Name: client_session_auth_status auth_status_constraint; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_auth_status
    ADD CONSTRAINT auth_status_constraint FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: identity_provider fk2b4ebc52ae5c3b34; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT fk2b4ebc52ae5c3b34 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_attributes fk3c47c64beacca966; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT fk3c47c64beacca966 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: federated_identity fk404288b92ef007a6; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT fk404288b92ef007a6 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_node_registrations fk4129723ba992f594; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT fk4129723ba992f594 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_session_note fk5edfb00ff51c2736; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_note
    ADD CONSTRAINT fk5edfb00ff51c2736 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: user_session_note fk5edfb00ff51d3472; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_session_note
    ADD CONSTRAINT fk5edfb00ff51d3472 FOREIGN KEY (user_session) REFERENCES public.user_session(id);


--
-- Name: client_session_role fk_11b7sgqw18i532811v7o2dv76; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_role
    ADD CONSTRAINT fk_11b7sgqw18i532811v7o2dv76 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: redirect_uris fk_1burs8pb4ouj97h5wuppahv9f; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT fk_1burs8pb4ouj97h5wuppahv9f FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: user_federation_provider fk_1fj32f6ptolw2qy60cd8n01e8; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT fk_1fj32f6ptolw2qy60cd8n01e8 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_session_prot_mapper fk_33a8sgqw18i532811v7o2dk89; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session_prot_mapper
    ADD CONSTRAINT fk_33a8sgqw18i532811v7o2dk89 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: realm_required_credential fk_5hg65lybevavkqfki3kponh9v; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT fk_5hg65lybevavkqfki3kponh9v FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_attribute fk_5hrm2vlf9ql5fu022kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu022kqepovbr FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: user_attribute fk_5hrm2vlf9ql5fu043kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu043kqepovbr FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: user_required_action fk_6qj3w1jw9cvafhe19bwsiuvmd; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT fk_6qj3w1jw9cvafhe19bwsiuvmd FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: keycloak_role fk_6vyqfe4cn4wlq8r6kt5vdsj5c; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_6vyqfe4cn4wlq8r6kt5vdsj5c FOREIGN KEY (realm) REFERENCES public.realm(id);


--
-- Name: realm_smtp_config fk_70ej8xdxgxd0b9hh6180irr0o; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT fk_70ej8xdxgxd0b9hh6180irr0o FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_default_roles fk_8aelwnibji49avxsrtuf6xjow; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT fk_8aelwnibji49avxsrtuf6xjow FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_attribute fk_8shxd6l3e9atqukacxgpffptw; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT fk_8shxd6l3e9atqukacxgpffptw FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: composite_role fk_a63wvekftu8jo1pnj81e7mce2; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_a63wvekftu8jo1pnj81e7mce2 FOREIGN KEY (composite) REFERENCES public.keycloak_role(id);


--
-- Name: authentication_execution fk_auth_exec_flow; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_flow FOREIGN KEY (flow_id) REFERENCES public.authentication_flow(id);


--
-- Name: authentication_execution fk_auth_exec_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authentication_flow fk_auth_flow_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT fk_auth_flow_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authenticator_config fk_auth_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT fk_auth_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_session fk_b4ao2vcvat6ukau74wbwtfqo1; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_session
    ADD CONSTRAINT fk_b4ao2vcvat6ukau74wbwtfqo1 FOREIGN KEY (session_id) REFERENCES public.user_session(id);


--
-- Name: user_role_mapping fk_c4fqv34p1mbylloxang7b1q3l; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT fk_c4fqv34p1mbylloxang7b1q3l FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_scope_client fk_c_cli_scope_client; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT fk_c_cli_scope_client FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_scope_client fk_c_cli_scope_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT fk_c_cli_scope_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_attributes fk_cl_scope_attr_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT fk_cl_scope_attr_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_role; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_role FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_user_session_note fk_cl_usr_ses_note; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_user_session_note
    ADD CONSTRAINT fk_cl_usr_ses_note FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: protocol_mapper fk_cli_scope_mapper; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_cli_scope_mapper FOREIGN KEY (client_scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_initial_access fk_client_init_acc_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT fk_client_init_acc_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: component_config fk_component_config; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT fk_component_config FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: component fk_component_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT fk_component_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: credential_attribute fk_cred_attr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential_attribute
    ADD CONSTRAINT fk_cred_attr FOREIGN KEY (credential_id) REFERENCES public.credential(id);


--
-- Name: realm_default_groups fk_def_groups_group; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: realm_default_groups fk_def_groups_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_default_roles fk_evudb1ppw84oxfax2drs03icc; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT fk_evudb1ppw84oxfax2drs03icc FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: fed_credential_attribute fk_fed_cred_attr; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.fed_credential_attribute
    ADD CONSTRAINT fk_fed_cred_attr FOREIGN KEY (credential_id) REFERENCES public.fed_user_credential(id);


--
-- Name: user_federation_mapper_config fk_fedmapper_cfg; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT fk_fedmapper_cfg FOREIGN KEY (user_federation_mapper_id) REFERENCES public.user_federation_mapper(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_fedprv; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_fedprv FOREIGN KEY (federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: associated_policy fk_frsr5s213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsr5s213xcx4wnkog82ssrfy FOREIGN KEY (associated_policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrasp13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrasp13xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog82sspmt; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82sspmt FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_resource fk_frsrho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog83sspmt; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog83sspmt FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog84sspmt; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog84sspmt FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: associated_policy fk_frsrpas14xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsrpas14xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrpass3xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrpass3xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_perm_ticket fk_frsrpo2128cx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrpo2128cx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_policy fk_frsrpo213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT fk_frsrpo213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_scope fk_frsrpos13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrpos13xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpos53xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpos53xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpp213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpp213xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_scope fk_frsrps213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrps213xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_scope fk_frsrso213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT fk_frsrso213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: composite_role fk_gr7thllb9lu8q4vqa4524jjy8; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_gr7thllb9lu8q4vqa4524jjy8 FOREIGN KEY (child_role) REFERENCES public.keycloak_role(id);


--
-- Name: user_consent_client_scope fk_grntcsnt_clsc_usc; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT fk_grntcsnt_clsc_usc FOREIGN KEY (user_consent_id) REFERENCES public.user_consent(id);


--
-- Name: user_consent fk_grntcsnt_user; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT fk_grntcsnt_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: group_attribute fk_group_attribute_group; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT fk_group_attribute_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: keycloak_group fk_group_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT fk_group_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: group_role_mapping fk_group_role_group; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: group_role_mapping fk_group_role_role; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_role FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_default_roles fk_h4wpd7w4hsoolni3h0sw7btje; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT fk_h4wpd7w4hsoolni3h0sw7btje FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_enabled_event_types fk_h846o4h0w8epx5nwedrf5y69j; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT fk_h846o4h0w8epx5nwedrf5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_events_listeners fk_h846o4h0w8epx5nxev9f5y69j; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT fk_h846o4h0w8epx5nxev9f5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: identity_provider_mapper fk_idpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT fk_idpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: idp_mapper_config fk_idpmconfig; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT fk_idpmconfig FOREIGN KEY (idp_mapper_id) REFERENCES public.identity_provider_mapper(id);


--
-- Name: keycloak_role fk_kjho5le2c0ral09fl8cm9wfw9; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_kjho5le2c0ral09fl8cm9wfw9 FOREIGN KEY (client) REFERENCES public.client(id);


--
-- Name: web_origins fk_lojpho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT fk_lojpho213xcx4wnkog82ssrfy FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_default_roles fk_nuilts7klwqw2h8m2b5joytky; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT fk_nuilts7klwqw2h8m2b5joytky FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: scope_mapping fk_ouse064plmlr732lxjcn1q5f1; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_ouse064plmlr732lxjcn1q5f1 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: scope_mapping fk_p3rh9grku11kqfrs4fltt7rnq; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_p3rh9grku11kqfrs4fltt7rnq FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: client fk_p56ctinxxb9gsk57fo49f9tac; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT fk_p56ctinxxb9gsk57fo49f9tac FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: protocol_mapper fk_pcm_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_pcm_realm FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: credential fk_pfyr0glasqyl0dei3kl69r6v0; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT fk_pfyr0glasqyl0dei3kl69r6v0 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: protocol_mapper_config fk_pmconfig; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT fk_pmconfig FOREIGN KEY (protocol_mapper_id) REFERENCES public.protocol_mapper(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope fk_realm_cli_scope; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT fk_realm_cli_scope FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: required_action_provider fk_req_act_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT fk_req_act_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_uris fk_resource_server_uris; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT fk_resource_server_uris FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: role_attribute fk_role_attribute_id; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT fk_role_attribute_id FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_supported_locales fk_supported_locales_realm; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT fk_supported_locales_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_federation_config fk_t13hpu1j94r2ebpekr39x5eu5; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT fk_t13hpu1j94r2ebpekr39x5eu5 FOREIGN KEY (user_federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: realm fk_traf444kk6qrkms7n56aiwq5y; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT fk_traf444kk6qrkms7n56aiwq5y FOREIGN KEY (master_admin_client) REFERENCES public.client(id);


--
-- Name: user_group_membership fk_user_group_user; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT fk_user_group_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: policy_config fkdc34197cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT fkdc34197cf864c4e43 FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: identity_provider_config fkdc4897cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT fkdc4897cf864c4e43 FOREIGN KEY (identity_provider_id) REFERENCES public.identity_provider(internal_id);


--
-- PostgreSQL database dump complete
--

\connect postgres

SET default_transaction_read_only = off;

--
-- PostgreSQL database dump
--

-- Dumped from database version 10.4
-- Dumped by pg_dump version 10.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: DATABASE postgres; Type: COMMENT; Schema: -; Owner: postgres
--

COMMENT ON DATABASE postgres IS 'default administrative connection database';


--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- PostgreSQL database dump complete
--

\connect template1

SET default_transaction_read_only = off;

--
-- PostgreSQL database dump
--

-- Dumped from database version 10.4
-- Dumped by pg_dump version 10.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: DATABASE template1; Type: COMMENT; Schema: -; Owner: postgres
--

COMMENT ON DATABASE template1 IS 'default template for new databases';


--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- PostgreSQL database dump complete
--

--
-- PostgreSQL database cluster dump complete
--

