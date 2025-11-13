import axios from 'axios';
// https://drainage-victoria-dot-nvidia.trycloudflare.com
const API_URL = 'https://drainage-victoria-dot-nvidia.trycloudflare.com'; // Your backend URL

export const axiosInstance = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Set or remove Authorization header
export const setAuthToken = token => {
  if (token) {
    axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    delete axiosInstance.defaults.headers.common['Authorization'];
  }
};
