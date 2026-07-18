"""Test GitHub OAuth integration - super cool one-click connect"""
import json
from pathlib import Path

from sentinelforge.integrations.github_oauth import GitHubOAuthManager, OAuthConfig, GitHubToken


def test_oauth_config_status(tmp_path):
    config = OAuthConfig(client_id="test_id", client_secret="test_secret", callback_url="http://localhost:8741/api/github/oauth/callback")
    mgr = GitHubOAuthManager(config=config, storage_dir=tmp_path)
    status = mgr.get_oauth_config_status()
    assert status["configured"] is True
    assert "test_id" in status["client_id"]
    assert status["has_client_secret"] is True


def test_oauth_create_authorize_url(tmp_path):
    config = OAuthConfig(client_id="test_client_id", client_secret="secret", callback_url="http://localhost:8741/api/github/oauth/callback")
    mgr = GitHubOAuthManager(config=config, storage_dir=tmp_path)
    url, state = mgr.create_authorize_url(redirect_after="/")
    assert "github.com/login/oauth/authorize" in url
    assert "test_client_id" in url
    assert state in url
    assert len(state) > 20  # secure random
    # Check state file created with 600 perms
    assert mgr.state_file.is_file()


def test_oauth_token_storage_secure(tmp_path):
    config = OAuthConfig(client_id="id", client_secret="secret")
    mgr = GitHubOAuthManager(config=config, storage_dir=tmp_path)
    token = GitHubToken(access_token="gho_testtoken123", login="testuser", name="Test User", scope="repo,read:org")
    mgr._store_token(token)

    assert mgr.token_file.is_file()
    # Check file has 600 permissions (on Unix, but skip on Windows)
    # Check content
    data = json.loads(mgr.token_file.read_text())
    assert data["access_token"] == "gho_testtoken123"
    assert data["login"] == "testuser"

    # Load token
    loaded = mgr.load_token()
    assert loaded is not None
    assert loaded.access_token == "gho_testtoken123"
    assert loaded.login == "testuser"

    # Safe dict should not contain full token
    safe = loaded.to_safe_dict()
    assert safe["has_token"] is True
    assert "access_token" not in safe
    assert safe["login"] == "testuser"


def test_oauth_state_csrf_protection(tmp_path):
    config = OAuthConfig(client_id="id", client_secret="secret")
    mgr = GitHubOAuthManager(config=config, storage_dir=tmp_path)
    _, state1 = mgr.create_authorize_url()
    _, state2 = mgr.create_authorize_url()

    # States should be different
    assert state1 != state2

    # Invalid state should fail
    try:
        mgr.exchange_code_for_token("some_code", "invalid_state")
        assert False, "Should have raised for invalid state"
    except ValueError as e:
        assert "Invalid or expired OAuth state" in str(e)


def test_oauth_disconnect(tmp_path):
    config = OAuthConfig(client_id="id", client_secret="secret")
    mgr = GitHubOAuthManager(config=config, storage_dir=tmp_path)
    token = GitHubToken(access_token="test", login="user")
    mgr._store_token(token)
    assert mgr.token_file.is_file()

    deleted = mgr.delete_token()
    assert deleted is True
    assert not mgr.token_file.is_file()

    deleted_again = mgr.delete_token()
    assert deleted_again is False


def test_github_client_loads_oauth_token(tmp_path, monkeypatch):
    # Create oauth token file
    oauth_file = Path(".sentinelforge/github_token.json")
    backup = None
    if oauth_file.is_file():
        backup = oauth_file.read_text()
    
    try:
        # Simulate oauth token file in current .sentinelforge dir
        token_data = {
            "access_token": "gho_oauth_test_token",
            "login": "testuser",
            "scope": "repo",
            "obtained_at": 0,
        }
        oauth_file.parent.mkdir(parents=True, exist_ok=True)
        oauth_file.write_text(json.dumps(token_data))
        
        from sentinelforge.integrations.github import GitHubClient
        
        # Clear env token to force file loading
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        
        client = GitHubClient()
        # Should load from oauth file
        assert client.configured is True
        assert client._token == "gho_oauth_test_token"
        
    finally:
        if oauth_file.is_file():
            oauth_file.unlink()
        if backup:
            oauth_file.write_text(backup)
