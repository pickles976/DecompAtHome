from recomp.prompt import render_prompt


def test_init_writes_prompt_md(project):
    prompt = (project.path / "PROMPT.md").read_text()
    assert "demo" in prompt
    assert "policy is v1" in prompt
    assert "recomp work --once" in prompt


def test_prompt_uses_plugin_prompt_and_facts(project):
    text = render_prompt(project.path, base_url="http://x:1")
    assert "http://x:1" in text
    assert "t1-structure" in text


def test_host_agent_prompt_edit_is_policy_versioned(project):
    from recomp.policy import bump_policy, check_policy
    prompt_file = project.path / "plugins" / "generic" / "prompt.md"
    prompt_file.write_text(prompt_file.read_text() + "\n<!-- host edit -->\n")
    status, _ = check_policy(project.path)
    assert status == "stale", "editing plugin prompt.md must invalidate the policy lock"
    lock = bump_policy(project.path)
    assert lock["policy_version"] == 2
    assert "host edit" in render_prompt(project.path)


