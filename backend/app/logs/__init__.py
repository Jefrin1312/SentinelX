"""Log ingestion pipeline subpackage.

Raw Log -> Collector -> Parser -> Normalizer -> Event (-> Detection Engine)

The stages are deliberately separated so each can be unit tested in
isolation and explained clearly to an interviewer.
"""