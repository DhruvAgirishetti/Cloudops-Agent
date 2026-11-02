"""Plain-text rendering helpers for already validated investigation outputs."""

from cloudops_agent.investigation_output import InvestigationOutput


VALIDATION_DISCLAIMER = (
    "Citations are checked for request scope and existence; this does not guarantee "
    "that a claim is semantically supported by its cited evidence. Recommendations "
    "are advisory and are never automatically executed."
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


def _citations(streamlit: object, references: tuple[str, ...]) -> None:
    streamlit.caption("Citations: " + ", ".join(references))
