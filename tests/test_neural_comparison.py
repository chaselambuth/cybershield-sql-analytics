"""Neural models use training data only and expose compatible anomaly scores."""
import io
import json
import warnings

import joblib
import numpy as np
import pytest
from sklearn.base import clone
from sklearn.exceptions import ConvergenceWarning
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from threadpoolctl import threadpool_limits

from cybershield.db import ROOT
from cybershield.neural_comparison import NeuralMLP, NeuralAutoencoder, revised_candidates
from cybershield.research import response


def training():
    rng = np.random.default_rng(91)
    X = rng.lognormal(size=(96,7)); X[0,0] = np.nan
    return X, np.arange(96) % 8 == 0


@pytest.mark.parametrize('estimator',[NeuralMLP(max_iter=8), NeuralAutoencoder(max_iter=8)])
def test_neural_pipeline_keeps_training_transform_and_serialized_scores(estimator):
    X, y = training()
    pipeline = make_pipeline(SimpleImputer(strategy='median'),FunctionTransformer(np.log1p),StandardScaler(),clone(estimator))
    with warnings.catch_warnings(), threadpool_limits(limits=1):
        warnings.simplefilter('ignore',ConvergenceWarning)  # Deliberately short unit-test fit only.
        pipeline.fit(X,y)
        means = pipeline[-2].mean_.copy()
        scores = response(pipeline,X)
        response(pipeline,np.full((3,7),1e6))
        assert np.array_equal(means,pipeline[-2].mean_)
        assert scores.shape == (96,) and np.isfinite(scores).all()
        buffer=io.BytesIO(); joblib.dump(pipeline,buffer); buffer.seek(0)
        assert np.array_equal(scores,response(joblib.load(buffer),X))


def test_autoencoder_fits_benign_rows_and_uses_reconstruction_error():
    X,y=training(); X=np.nan_to_num(X)
    with warnings.catch_warnings(), threadpool_limits(limits=1):
        warnings.simplefilter('ignore',ConvergenceWarning)
        model=NeuralAutoencoder(max_iter=8).fit(X,y)
        assert model.training_rows_ == int((~y).sum())
        expected=np.mean((X-model.network_.predict(X))**2,axis=1)
        assert np.array_equal(model.decision_function(X),expected)
        assert model.network_.hidden_layer_sizes == (16,4,16)


def test_revised_roster_replaces_exactly_two_models_and_retains_baselines():
    config=json.loads((ROOT/'configs/neural_comparison_v1.json').read_text())
    models=revised_candidates(config,10.)
    assert list(models) == config['models'] and len(models)==8
    assert 'Linear SVM' not in models and 'Extra trees' not in models
    assert 'Logistic regression' in models and 'CatBoost' in models
    assert models['Neural MLP'][-1].hidden_layer_sizes == (32,16)
    assert models['Neural autoencoder'][-1].hidden_layer_sizes == (16,4,16)
