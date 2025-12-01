use common_enums::enums;
use common_utils::{request::Method, types::StringMinorUnit};
use hyperswitch_domain_models::{
    payment_method_data::{CardRedirectData, PaymentMethodData},
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use masking::Secret;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::types::{RefundsResponseRouterData, ResponseRouterData};

pub struct YocoRouterData<T> {
    pub amount: StringMinorUnit,
    pub router_data: T,
}

impl<T> From<(StringMinorUnit, T)> for YocoRouterData<T> {
    fn from((amount, item): (StringMinorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

// Request for PSP redirect - Yoco will return a redirect URL
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct YocoPaymentsRequest {
    amount: StringMinorUnit,
    currency: String,
    #[serde(rename = "successUrl")]
    success_url: String,
    #[serde(rename = "cancelUrl")]
    cancel_url: String,
    #[serde(rename = "failureUrl")]
    failure_url: String,
}

impl TryFrom<&YocoRouterData<&PaymentsAuthorizeRouterData>> for YocoPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &YocoRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::CardRedirect(card_redirect_data) => {
                // Accept any CardRedirect variant for PSP redirect flow
                match card_redirect_data {
                    CardRedirectData::CardRedirect {} => {},
                    CardRedirectData::Knet {} => {},
                    CardRedirectData::Benefit {} => {},
                    CardRedirectData::MomoAtm {} => {},
                }
                
                let return_url = item.router_data.request.router_return_url.clone()
                    .ok_or(errors::ConnectorError::MissingRequiredField { 
                        field_name: "return_url" 
                    })?;
                
                Ok(Self {
                    amount: item.amount.clone(),
                    currency: item.router_data.request.currency.to_string().to_uppercase(),
                    success_url: return_url.clone(),
                    cancel_url: return_url.clone(),
                    failure_url: return_url,
                })
            },
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported. Use CardRedirect payment method.".to_string()
            ).into()),
        }
    }
}

// Auth Struct
pub struct YocoAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for YocoAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Payment Status
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum YocoPaymentStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
    Pending,
    Created,
    Completed,
}

impl From<YocoPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: YocoPaymentStatus) -> Self {
        match item {
            YocoPaymentStatus::Succeeded => Self::Charged,
            YocoPaymentStatus::Failed => Self::Failure,
            YocoPaymentStatus::Processing => Self::Authorizing,
            YocoPaymentStatus::Pending => Self::Pending,
            YocoPaymentStatus::Created => Self::AuthenticationPending,
            YocoPaymentStatus::Completed => Self::Charged,
        }
    }
}

// Payment Response with redirect URL
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct YocoPaymentsResponse {
    status: YocoPaymentStatus,
    id: String,
    #[serde(rename = "redirectUrl")]
    redirect_url: Option<String>,
}

impl<F, T> TryFrom<ResponseRouterData<F, YocoPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, YocoPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = common_enums::AttemptStatus::from(item.response.status);
        
        // For PSP redirect, we need to return the redirect URL
        let redirection_data = item.response.redirect_url
            .as_ref()
            .and_then(|url_str| {
                Url::parse(url_str)
                    .ok()
                    .map(|parsed_url| {
                        hyperswitch_domain_models::router_response_types::RedirectForm::from((
                            parsed_url,
                            Method::Get,
                        ))
                    })
            });

        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: Box::new(redirection_data),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// REFUND
#[derive(Default, Debug, Serialize)]
pub struct YocoRefundRequest {
    pub amount: StringMinorUnit,
}

impl<F> TryFrom<&YocoRouterData<&RefundsRouterData<F>>> for YocoRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &YocoRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.amount.to_owned(),
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Copy, Serialize, Default, Deserialize, Clone)]
pub enum RefundStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Succeeded => Self::Success,
            RefundStatus::Failed => Self::Failure,
            RefundStatus::Processing => Self::Pending,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    id: String,
    status: RefundStatus,
}

impl TryFrom<RefundsResponseRouterData<Execute, RefundResponse>> for RefundsRouterData<Execute> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, RefundResponse>> for RefundsRouterData<RSync> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<RSync, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct YocoErrorResponse {
    pub status: Option<u16>,
    pub message: Option<String>,
    pub description: Option<String>,
    pub code: Option<String>,
    pub reason: Option<String>,
}
