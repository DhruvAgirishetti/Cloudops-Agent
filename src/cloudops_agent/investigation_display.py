"""Plain-text rendering helpers for already validated investigation outputs."""

from cloudops_agent.investigation_output import InvestigationOutput
from cloudops_agent.meta_provider import MetaTokenUsage


VALIDATION_DISCLAIMER = (
    "Recommendations are advisory only; CloudOps Agent never automatically executes, "
    "applies, or verifies them. Citations are checked for scope and existence, not "
    "semantic correctness."
)


def render_investigation_output(streamlit: object, output: InvestigationOutput) -> None:
    """Render an `InvestigationOutput`; text fields are rendered as plain text."""
    streamlit.markdown("**Summary**")
    streamlit.text(output.summary.text)
    _citations(streamlit, output.summary.references)

    streamlit.markdown("**Observations**")
    for index, observation in enumerate(output.observations, start=1):
        streamlit.markdown(f"Observation {index} · {observation.basis.replace('_', ' ')}")
        streamlit.text(observation.claim)
        _citations(streamlit, observation.references)
        if observation.uncertainty.present:
            streamlit.text(f"Uncertainty: {observation.uncertainty.note}")
        else:
            streamlit.caption("Uncertainty: none stated.")

    streamlit.markdown("**Limitations**")
    for limitation in output.limitations:
        streamlit.text(limitation.text)
        _citations(streamlit, limitation.references)

    streamlit.markdown("**Recommendations**")
    for recommendation in output.recommendations:
        streamlit.markdown(
            f"{recommendation.type.title()} · {recommendation.priority.title()} priority"
        )
        streamlit.text(recommendation.action)
        streamlit.caption("Rationale")
        streamlit.text(recommendation.rationale)
        _citations(streamlit, recommendation.references)
        if recommendation.uncertainty.present:
            streamlit.text(f"Uncertainty: {recommendation.uncertainty.note}")
        else:
            streamlit.caption("Uncertainty: none stated.")


def render_token_usage(streamlit: object, usage: MetaTokenUsage | None) -> None:
    """Display provider-reported aggregate counters only."""
    if usage is None:
        streamlit.caption("Token usage metadata was not returned by the provider.")
        return
    counts = []
    if usage.prompt_tokens is not None:
        counts.append(f"prompt {usage.prompt_tokens:,}")
    if usage.completion_tokens is not None:
        counts.append(f"completion {usage.completion_tokens:,}")
    if usage.reasoning_tokens is not None:
        counts.append(f"reasoning {usage.reasoning_tokens:,} (included in completion)")
    if counts:
        streamlit.caption("Provider-reported token usage: " + " · ".join(counts))
    else:
        streamlit.caption("Token usage metadata was not returned by the provider.")


def _citations(streamlit: object, references: tuple[str, ...]) -> None:
    streamlit.caption("Citations: " + ", ".join(references))
